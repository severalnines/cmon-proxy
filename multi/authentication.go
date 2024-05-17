package multi

// Copyright 2022 Severalnines AB
//
// This file is part of cmon-proxy.
//
// cmon-proxy is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 2 of the License.
//
// cmon-proxy is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with cmon-proxy. If not, see <https://www.gnu.org/licenses/>.

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/rs/xid"
	cmonapi "github.com/severalnines/cmon-proxy/cmon/api"
	"github.com/severalnines/cmon-proxy/config"
	"github.com/severalnines/cmon-proxy/multi/api"
	"github.com/severalnines/cmon-proxy/multi/router"
	"github.com/severalnines/cmon-proxy/rpcserver/session"

	"go.uber.org/zap"
)

type SessionData struct {
	User  *config.ProxyUser
	Login time.Time
	LastActive time.Time
}

var (
	// session ID <-> session data map
	sesss    = make(map[string]*SessionData)
	sesssMtx sync.RWMutex

	// the user key for the context (we put the user object there)
	userKey = "user"
	// the key in the browser side cookie (encrypted)
	sessIdKey = "s"
)

func cleanupOldSessions(p *Proxy) {
    sesssMtx.Lock()

    usernames := make([]string, 0, len(sesss))
    invalidate := make([]string, 0)
    // Collect the outdated sessions
    for sessionId, data := range sesss {
        if time.Since(data.LastActive) > session.SessionTTL {
            invalidate = append(invalidate, sessionId)

            // Audit log of server side logouts
            if data.User != nil {
                zap.L().Info("[AUDIT] Logout", zap.String("user", data.User.Username), zap.String("reason", "TTL"))
            }
        } else if data.User != nil {
            // Collect username from the active user sessions
            usernames = append(usernames, data.User.Username)
        }
    }

    // Invalidate outdated sessions
    for _, sessionId := range invalidate {
        delete(sesss, sessionId)
    }

    sesssMtx.Unlock()

    if p == nil {
        return
    }

    // Additional cleanup for user routers
    for username := range p.r {
        hasSessionForUser := false
        for _, loggedinUser := range usernames {
            if loggedinUser == username {
                hasSessionForUser = true
                break
            }
        }
		// delete routers for no longer logged in (LDAP?) users...
        if !hasSessionForUser && username != router.DefaultRouter {
            mtx.Lock()
            delete(p.r, username)
            mtx.Unlock()
        }
    }
}

func StartSessionCleanupScheduler(p *Proxy) {
    ticker := time.NewTicker(30 * time.Minute)
    go func() {
        for range ticker.C {
            cleanupOldSessions(p)
        }
    }()
}

func refreshSession(sessionId string) {
    sesssMtx.Lock()
    defer sesssMtx.Unlock()

    if session, exists := sesss[sessionId]; exists {
        session.LastActive = time.Now() // Update the last active time to the current time
        sesss[sessionId] = session     // Put the updated session back into the map
    }
}

func isLDAPSession(ctx *gin.Context) (isLDAPSession bool, ldapUsername string) {
	if ctx == nil {
		return false, ""
	}
	isLDAPSession = false
	if user := getUserForSession(ctx); user != nil && user.LdapUser {
		isLDAPSession = true
		ldapUsername = user.Username
	}
	return
}

// retrieves the ProxyUser object for the actual session
func getUserForSession(ctx *gin.Context) *config.ProxyUser {
	if ctx == nil {
		return nil
	}
	s := sessions.Default(ctx)
	// get the unique ID
	sessionId, _ := s.Get(sessIdKey).(string)

	sesssMtx.RLock()
	defer sesssMtx.RUnlock()
	if data, found := sesss[sessionId]; found && data != nil {
		return data.User
	}
	return nil
}

func setUserForSession(ctx *gin.Context, user *config.ProxyUser) {
	s := sessions.Default(ctx)

	sesssMtx.Lock()
	defer sesssMtx.Unlock()

	// get the unique ID
	sessionId, _ := s.Get(sessIdKey).(string)

	// it might be a logout (in case of 'nil' user)
	if user == nil {
		// remove the data and destroy the session
		delete(sesss, sessionId)
		session.SessionDestroy(ctx)
		return
	}

	if len(sessionId) < 1 {
		// generate one for new sessions
		guid := xid.New()
		sessionId = guid.String()
		s.Set(sessIdKey, sessionId)
		if err := s.Save(); err != nil {
			zap.L().Fatal("Session.Save() error: " + err.Error())
		}
	}

	// save the user into our session storage using the sessionID
	sesss[sessionId] = &SessionData{
		User:  user,
		Login: time.Now(),
		LastActive: time.Now(),
	}
	ctx.Set(userKey, user)
}

func getSessionIdFromRequest(ctx *gin.Context) string {
	s := sessions.Default(ctx) // Use the same session management library to obtain the session

	// Attempt to retrieve the session ID stored under sessIdKey
	if sessionId, ok := s.Get(sessIdKey).(string); ok && sessionId != "" {
		return sessionId
	}
	return "" // Return an empty string if no session ID is found
}

// RPCAuthCheck is a middleware method
func (p *Proxy) RPCAuthMiddleware(ctx *gin.Context) {
	user := getUserForSession(ctx)
	if user == nil {
		ctx.JSON(http.StatusUnauthorized,
			&cmonapi.WithResponseData{
				RequestStatus: cmonapi.RequestStatusAuthRequired,
				ErrorString:   "authentication is required",
			})
		ctx.Abort()
		return
	}
	// we store the 'user' object in context
	ctx.Set(userKey, user)
}

// Attempts to do LDAP login when there are any controllers
// configured to use LDAP authentication
// (call this only after we checked that there is no such local user)
func (p *Proxy) ldapLogin(ctx *gin.Context, req *api.LoginRequest, resp *api.LoginResponse) bool {
	// missing/incomplete configuration
	if p == nil || p.cfg == nil || len(p.cfg.Instances) < 1 {
		return false
	}
	// check if we have any cmon configured to use LDAP
	useLdap := false
	for _, cmon := range p.cfg.Instances {
		if cmon != nil && cmon.UseLdap {
			useLdap = true
			break
		}
	}
	if !useLdap {
		return false
	}
	// create a router for this login attempt (if there is not already one)
	r, found := p.r[req.Username]
	if !found || r == nil {
		var err error
		r, err = router.New(p.cfg)
		if err != nil {
			fmt.Sprintf("Can't create router for LDAP login: %s", err.Error())
			return false
		}
	}

	// configure this router to use the specified LDAP credentials for LDAP enabled cmon instances
	r.Ldap.Use = true
	r.Ldap.Username = req.Username
	r.Ldap.Password = req.Password

	zap.L().Info(
		fmt.Sprintf("[AUDIT] LDAP authentication attempt '%s' (source %s / %s)",
			req.Username, ctx.ClientIP(), ctx.Request.UserAgent()))

	r.Authenticate() // attempts to authenticate

	// check if any LDAP enabled cmon's has succeed
	ldapSucceed := false
	for _, addr := range r.Config.ControllerUrls() {
		if cmon := r.Cmon(addr); cmon != nil && cmon.Client != nil && cmon.Client.Instance != nil && cmon.Client.Instance.UseLdap {
			user := cmon.Client.User()
			if user != nil {
				ldapSucceed = true
				// construct a syntetic LDAP user from the User object we got from cmon
				setUserForSession(ctx, &config.ProxyUser{
					Username:     user.UserName,
					LdapUser:     true,
					FirstName:    user.FirstName,
					LastName:     user.LastName,
					EmailAddress: user.EmailAddress,
				})
			}
		}
	}

	// okay, keep this router as login succeed to some of the cmon's
	if user := getUserForSession(ctx); ldapSucceed && user != nil {
		p.r[req.Username] = r

		// LDAP auth succeed, wohoo, return the syntetic proxy user
		resp.RequestStatus = cmonapi.RequestStatusOk
		resp.User = user

		return true
	}

	zap.L().Info(
		fmt.Sprintf("[AUDIT] LDAP authentication (user %s) has failed to all cmon instances. (source %s / %s)",
			req.Username, ctx.ClientIP(), ctx.Request.UserAgent()))

	return false
}

// RPCLoginHandler handlers the login requests
func (p *Proxy) RPCAuthLoginHandler(ctx *gin.Context) {
	var req api.LoginRequest
	var resp api.LoginResponse

	resp.WithResponseData = &cmonapi.WithResponseData{
		RequestStatus:    cmonapi.RequestStatusOk,
		RequestProcessed: cmonapi.NullTime{T: time.Now()},
	}

	if ctx.Request.Method == http.MethodPost {
		if err := ctx.BindJSON(&req); err != nil {
			cmonapi.CtxWriteError(ctx,
				cmonapi.NewError(cmonapi.RequestStatusInvalidRequest,
					fmt.Sprint("Invalid request:", err.Error())))
			return
		}
	}

	user, err := p.r[router.DefaultRouter].Config.GetUser(req.Username)
	if err != nil {
		// ldapLogin returns true if it was okay and it sets the user for session
		if !p.ldapLogin(ctx, &req, &resp) {
			resp.RequestStatus = cmonapi.RequestStatusAccessDenied
			resp.ErrorString = fmt.Sprintf("user error: %s", err.Error())
		}
	}

	// user might be nil and we may succeed in case of LDAP
	if user != nil {
		if err := user.ValidatePassword(req.Password); err != nil {
			resp.RequestStatus = cmonapi.RequestStatusAccessDenied
			resp.ErrorString = fmt.Sprintf("password error: %s", err.Error())
		} else {
			resp.RequestStatus = cmonapi.RequestStatusOk
			resp.User = user.Copy(false)

			setUserForSession(ctx, user)
		}
	}

	zap.L().Info(
		fmt.Sprintf("[AUDIT] Login attempt %s '%s' (source %s / %s)",
			resp.RequestStatus, req.Username, ctx.ClientIP(), ctx.Request.UserAgent()))

	ctx.JSON(cmonapi.RequestStatusToStatusCode(resp.RequestStatus), resp)
}

// RPCCheckHandler checks if the user has logged in
func (p *Proxy) RPCAuthCheckHandler(ctx *gin.Context) {
	var resp api.LoginResponse
	resp.WithResponseData = &cmonapi.WithResponseData{
		RequestProcessed: cmonapi.NullTime{T: time.Now()},
		RequestStatus:    cmonapi.RequestStatusAuthRequired,
		ErrorString:      "not authenticated",
	}
	sessionId := getSessionIdFromRequest(ctx)
	if sessionId != "" {
		refreshSession(sessionId)
	}

	if u := getUserForSession(ctx); u != nil {
		resp.User = u.Copy(false)
		resp.RequestStatus = cmonapi.RequestStatusOk
		resp.ErrorString = ""
	}

	ctx.JSON(cmonapi.RequestStatusToStatusCode(resp.RequestStatus), resp)
}

// RPCLogoutHandler handlers the explicit logout requests
func (p *Proxy) RPCAuthLogoutHandler(ctx *gin.Context) {
	if proxyUser := getUserForSession(ctx); proxyUser != nil {
		zap.L().Info(
			fmt.Sprintf("[AUDIT] Logout '%s' (explicit) (source %s / %s)",
				proxyUser.Username, ctx.ClientIP(), ctx.Request.UserAgent()))
		// perform logout
		setUserForSession(ctx, nil)

		// also make sure we get rid of any unused routers
		defer cleanupOldSessions(p)
	}

	var resp cmonapi.WithResponseData
	resp.RequestStatus = cmonapi.RequestStatusOk

	ctx.JSON(cmonapi.RequestStatusToStatusCode(resp.RequestStatus), resp)
}

func (p *Proxy) RPCAuthUpdateUserHandler(ctx *gin.Context) {
	var req api.UpdateUserRequest
	var resp api.LoginResponse
	resp.WithResponseData = &cmonapi.WithResponseData{
		RequestProcessed: cmonapi.NullTime{T: time.Now()},
		RequestStatus:    cmonapi.RequestStatusAuthRequired,
		ErrorString:      "not authenticated",
	}

	if err := ctx.BindJSON(&req); err != nil || req.User == nil {
		cmonapi.CtxWriteError(ctx,
			cmonapi.NewError(cmonapi.RequestStatusInvalidRequest,
				fmt.Sprint("Invalid request:", err.Error())))
		return
	}

	if u := getUserForSession(ctx); u != nil {
		if u.Username != req.User.Username {
			resp.RequestStatus = cmonapi.RequestStatusAccessDenied
			resp.ErrorString = "wrong username"
		} else if err := req.User.Validate(); err != nil {
			resp.RequestStatus = cmonapi.RequestStatusInvalidRequest
			resp.ErrorString = "wrong user: " + err.Error()
		} else {
			// we do not allow updating password from this request
			req.User.PasswordHash = ""
			if err := p.r[router.DefaultRouter].Config.UpdateUser(req.User); err != nil {
				resp.RequestStatus = cmonapi.RequestStatusUnknownError
				resp.ErrorString = "failed to update user: " + err.Error()
			} else {
				// also update the user in session
				updatedUser, _ := p.r[router.DefaultRouter].Config.GetUser(req.User.Username)
				setUserForSession(ctx, updatedUser)
				// return the updated user instance
				resp.User = updatedUser.Copy(false)

				resp.RequestStatus = cmonapi.RequestStatusOk
				resp.ErrorString = ""
			}
		}
	}

	ctx.JSON(cmonapi.RequestStatusToStatusCode(resp.RequestStatus), resp)
}

func (p *Proxy) RPCAuthSetPasswordHandler(ctx *gin.Context) {
	var req api.SetPasswordRequest
	var resp api.LoginResponse
	resp.WithResponseData = &cmonapi.WithResponseData{
		RequestProcessed: cmonapi.NullTime{T: time.Now()},
		RequestStatus:    cmonapi.RequestStatusAuthRequired,
		ErrorString:      "not authenticated",
	}

	if ctx.Request.Method == http.MethodPost {
		if err := ctx.BindJSON(&req); err != nil {
			cmonapi.CtxWriteError(ctx,
				cmonapi.NewError(cmonapi.RequestStatusInvalidRequest,
					fmt.Sprint("Invalid request:", err.Error())))
			return
		}
	}

	if u := getUserForSession(ctx); u != nil {
		resp.User = u.Copy(false)

		if err := u.ValidatePassword(req.OldPassword); err != nil {
			resp.RequestStatus = cmonapi.RequestStatusAccessDenied
			resp.ErrorString = "wrong old password"
		} else if len(req.NewPassword) < 1 {
			resp.RequestStatus = cmonapi.RequestStatusInvalidRequest
			resp.ErrorString = "invalid new password"
		} else {
			resp.RequestStatus = cmonapi.RequestStatusOk
			resp.ErrorString = ""

			u.SetPassword(req.NewPassword)
			if err := p.r[router.DefaultRouter].Config.UpdateUser(u); err != nil {
				resp.RequestStatus = cmonapi.RequestStatusUnknownError
				resp.ErrorString = "failed to update user: " + err.Error()
			} else {
				// also update the user in session
				setUserForSession(ctx, u)

				resp.RequestStatus = cmonapi.RequestStatusOk
				resp.ErrorString = ""
			}
		}
	}

	ctx.JSON(cmonapi.RequestStatusToStatusCode(resp.RequestStatus), resp)
}
