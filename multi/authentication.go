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

	"github.com/severalnines/cmon-proxy/cmon"

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
	User       *config.ProxyUser
	Login      time.Time
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
		sesss[sessionId] = session      // Put the updated session back into the map
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
func isCMONSession(ctx *gin.Context) (isCMONSession bool, cmonUsername string) {
	if ctx == nil {
		return false, ""
	}
	isCMONSession = false
	if user := getUserForSession(ctx); user != nil && user.CMONUser {
		isCMONSession = true
		cmonUsername = user.Username
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
		User:       user,
		Login:      time.Now(),
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

func (p *Proxy) authByCookie(ctx *gin.Context, req *api.LoginRequest, resp *api.LoginResponse) bool {
	if p == nil || p.cfg == nil || len(p.cfg.Instances) < 1 || len(p.cfg.SingleController) < 1 {
		return false
	}

	var authController *config.CmonInstance
	for _, cmon := range p.cfg.Instances {
		if cmon != nil && cmon.Xid == p.cfg.SingleController {
			authController = cmon
			break
		}
	}

	if authController == nil {
		return false
	}

	// create a router for this login attempt (if there is not already one)
	r, found := p.r[req.Username]
	if !found || r == nil {
		var err error
		r, err = router.New(p.cfg)
		if err != nil {
			fmt.Sprintf("Can't create router for authentication: %s", err.Error())
			return false
		}
	}

	CMONSid, err := ctx.Cookie("cmon-sid")
	if err != nil {
		zap.L().Info(
			fmt.Sprintf("[AUDIT] Cookes are not enabled or cmon-sid cookie is missing"))
		return false
	}
	CMONCookie := &http.Cookie{
		Name:  "cmon-sid",
		Value: CMONSid,
	}

	// test authentication before writing anything in state
	testInstance := authController.Copy()
	testClient := cmon.NewClient(testInstance, r.Config.Timeout)
	testClient.SetSessionCookie(CMONCookie)
	if err := testClient.AuthenticateWithCookie(); err != nil {
		zap.L().Info(
			fmt.Sprintf("[AUDIT] CMON controller test authentication (user %s) has failed to controller (%s). (source %s / %s), error: %s",
				req.Username, authController.Url, ctx.ClientIP(), ctx.Request.UserAgent(), err.Error()))
		return false
	}

	r.CMONSid = CMONCookie

	r.Sync()
	controller := r.Cmon(authController.Url)
	// just in case if wrong controller was retrieved by Url
	if controller.Xid() != p.cfg.SingleController {
		zap.L().Info(
			fmt.Sprintf("[AUDIT] Retrieved controller (%s) could not be identified as the single controller (%s)",
				controller.Xid(), p.cfg.SingleController))
		return false
	}
	zap.L().Info(
		fmt.Sprintf("controller.Client.ses '%s'", controller.Client.GetSessionCookie()))

	if err := controller.Client.AuthenticateWithCookie(); err != nil {
		zap.L().Info(
			fmt.Sprintf("[AUDIT] CMON controller authentication with cookie (user %s) has failed to controller (%s). (source %s / %s), error: %s",
				req.Username, authController.Url, ctx.ClientIP(), ctx.Request.UserAgent(), err.Error()))
		return false
	}

	user := controller.Client.User()
	loginSucceed := false
	if user != nil {
		loginSucceed = true
		// construct a synthetic user from the User object we got from cmon
		setUserForSession(ctx, &config.ProxyUser{
			Username:     user.UserName,
			LdapUser:     user.Origin == "LDAP",
			CMONUser:     user.Origin == "CmonDb",
			ControllerId: controller.Xid(),
			FirstName:    user.FirstName,
			LastName:     user.LastName,
			EmailAddress: user.EmailAddress,
		})
	}

	// okay, keep this router as login succeed to some of the cmon's
	if user := getUserForSession(ctx); loginSucceed && user != nil {
		p.r[user.Username] = r

		resp.RequestStatus = cmonapi.RequestStatusOk
		resp.User = user

		return true
	}

	zap.L().Info(
		fmt.Sprintf("[AUDIT] CMON controller authentication (user %s) has failed to controller (%s). (source %s / %s)",
			req.Username, authController.Url, ctx.ClientIP(), ctx.Request.UserAgent()))

	return false
}

// Attempts to do login in controllers when there are any controllers
// configured to use LDAP authentication or CMON authentication
// (call this only after we checked that there is no such local user)
func (p *Proxy) controllerLogin(ctx *gin.Context, req *api.LoginRequest, resp *api.LoginResponse) bool {
	// missing/incomplete configuration
	if p == nil || p.cfg == nil || len(p.cfg.Instances) < 1 {
		return false
	}
	// check if we have any cmon configured to use LDAP or CMON authentication
	useController := false
	for _, cmon := range p.cfg.Instances {
		if cmon != nil && (cmon.UseLdap || cmon.UseCmonAuth) {
			useController = true
			break
		}
	}
	if !useController {
		return false
	}

	r, err := router.New(p.cfg)
	if err != nil {
		fmt.Sprintf("Can't create router for controller login: %s", err.Error())
		return false
	}

	// configure this router to use the specified controller credentials for cmon auth or ldap enabled cmon instances
	r.AuthController.Use = true
	r.AuthController.Username = req.Username
	r.AuthController.Password = req.Password

	zap.L().Info(
		fmt.Sprintf("[AUDIT] Controller authentication attempt '%s' (source %s / %s)",
			req.Username, ctx.ClientIP(), ctx.Request.UserAgent()))

	r.Authenticate() // attempts to authenticate
	user := r.GetControllerUser()

	if user != nil {
		existsRouter, found := p.r[req.Username]
		if found && existsRouter != nil {
			existsRouter.AuthController = router.AuthController{ // Create a new object without preserving reference
				Use:      r.AuthController.Use,
				Username: r.AuthController.Username,
				Password: r.AuthController.Password,
			}
			existsRouter.Authenticate()
			user = existsRouter.GetControllerUser()
			r = existsRouter
		}
	}

	authSucceed := user != nil
	if authSucceed {
		setUserForSession(ctx, &config.ProxyUser{
			Username:     user.UserName,
			LdapUser:     user.Origin == "LDAP",
			CMONUser:     user.Origin == "CmonDb",
			FirstName:    user.FirstName,
			LastName:     user.LastName,
			EmailAddress: user.EmailAddress,
			Admin:        false,
		})
	}

	// okay, keep this router as login succeed to some of the cmon's
	if user := getUserForSession(ctx); authSucceed && user != nil {
		p.r[req.Username] = r

		// Controller auth succeed, wohoo, return the syntetic proxy user
		resp.RequestStatus = cmonapi.RequestStatusOk
		resp.User = user

		return true
	}

	zap.L().Info(
		fmt.Sprintf("[AUDIT] Controllers authentication (user %s) has failed to all cmon instances. (source %s / %s)",
			req.Username, ctx.ClientIP(), ctx.Request.UserAgent()))

	return false
}

func (p *Proxy) RPCAuthCookieHandler(ctx *gin.Context) {
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

	loginSuccess := p.authByCookie(ctx, &req, &resp)
	if !loginSuccess {
		resp.RequestStatus = cmonapi.RequestStatusAccessDenied
		resp.ErrorString = "Authentication failed"
	}

	zap.L().Info(
		fmt.Sprintf("[AUDIT] Login attempt %s '%s' (source %s / %s)",
			resp.RequestStatus, req.Username, ctx.ClientIP(), ctx.Request.UserAgent()))

	ctx.JSON(cmonapi.RequestStatusToStatusCode(resp.RequestStatus), resp)
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
		externalLoginSucceed := p.controllerLogin(ctx, &req, &resp)
		if !externalLoginSucceed {
			resp.RequestStatus = cmonapi.RequestStatusAccessDenied
			resp.ErrorString = "User not found or wrong password"
		}
	}

	// user might be nil and we may succeed in case of controller auth
	if user != nil {
		if err := user.ValidatePassword(req.Password); err != nil {
			resp.RequestStatus = cmonapi.RequestStatusAccessDenied
			resp.ErrorString = "User not found or wrong password"
		} else {
			resp.RequestStatus = cmonapi.RequestStatusOk
			user = user.Copy(false)
			user.Admin = true
			resp.User = user

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
	// I wanted to logout in available controllers
	// The reason for this was making ssh console session to terminate as well
	// But it seems that logging out in cmon does not terminate ssh console session
	// I think this could be useful so will just leave this commented for now
	/**
	@todo get back to this once this is addressed: https://severalnines.atlassian.net/browse/CLUS-4104
	xids := make([]string, 0)
	for _, addr := range p.Router(ctx).Urls() {
		c := p.Router(ctx).Cmon(addr)
		if c == nil {
			continue
		}
		mtx.Lock()
		instance := controllerStatusCache[addr]
		mtx.Unlock()
		value := c.Xid()
		if instance.Status == api.Ok && value != "" {
			xids = append(xids, value)
		}
	}
	if len(xids) > 0 {
		go p.RPCProxyMany(ctx, xids, "logout", make([]byte, 0))
	}
	*/

	var resp cmonapi.WithResponseData
	resp.RequestStatus = cmonapi.RequestStatusOk

	ctx.JSON(cmonapi.RequestStatusToStatusCode(resp.RequestStatus), resp)
}

func (p *Proxy) RPCAuthRegisterUserHandler(ctx *gin.Context) {
	var req api.RegisterUserRequest
	var resp api.LoginResponse
	resp.WithResponseData = &cmonapi.WithResponseData{
		RequestProcessed: cmonapi.NullTime{T: time.Now()},
		RequestStatus:    cmonapi.RequestStatusOk,
		ErrorString:      "",
	}

	if p == nil || p.cfg == nil {
		ctx.JSON(cmonapi.RequestStatusToStatusCode(resp.RequestStatus), resp)
		resp.RequestStatus = cmonapi.RequestStatusUnknownError
		resp.ErrorString = "Internal server error"
		return
	}

	// We are not allowing to register more than one admin user
	if len(p.cfg.Users) > 0 {
		resp.RequestStatus = cmonapi.RequestStatusAccessDenied
		resp.ErrorString = "Admin user already exists"
		ctx.JSON(cmonapi.RequestStatusToStatusCode(resp.RequestStatus), resp)
		return
	}

	if err := ctx.BindJSON(&req); err != nil {
		resp.RequestStatus = cmonapi.RequestStatusInvalidRequest
		resp.ErrorString = "Invalid request " + err.Error()
		ctx.JSON(cmonapi.RequestStatusToStatusCode(resp.RequestStatus), resp)
		return
	}

	if req.User == nil {
		resp.RequestStatus = cmonapi.RequestStatusInvalidRequest
		resp.ErrorString = "Invalid request"
		ctx.JSON(cmonapi.RequestStatusToStatusCode(resp.RequestStatus), resp)
		return
	}

	proxyUser := req.User.Copy(true)
	proxyUser.PasswordHash = ""
	if len(req.User.Password) < 1 {
		resp.RequestStatus = cmonapi.RequestStatusInvalidRequest
		resp.ErrorString = "Invalid password"
		ctx.JSON(cmonapi.RequestStatusToStatusCode(resp.RequestStatus), resp)
		return
	}
	if err := proxyUser.SetPassword(req.User.Password); err != nil {
		resp.RequestStatus = cmonapi.RequestStatusInvalidRequest
		resp.ErrorString = "Invalid password"
		ctx.JSON(cmonapi.RequestStatusToStatusCode(resp.RequestStatus), resp)
		return
	}

	if err := p.cfg.AddUser(proxyUser); err != nil {
		resp.RequestStatus = cmonapi.RequestStatusUnknownError
		resp.ErrorString = "Failed to add user: " + err.Error()
		ctx.JSON(cmonapi.RequestStatusToStatusCode(resp.RequestStatus), resp)
		return
	}

	if err := p.cfg.Save(); err != nil {
		resp.RequestStatus = cmonapi.RequestStatusUnknownError
		resp.ErrorString = "Failed to save config " + err.Error()
		ctx.JSON(cmonapi.RequestStatusToStatusCode(resp.RequestStatus), resp)
		return
	}

	resp.User = proxyUser.Copy(false)
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
