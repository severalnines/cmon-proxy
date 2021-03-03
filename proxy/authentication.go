package proxy

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
	"github.com/severalnines/cmon-proxy/proxy/api"
	"github.com/severalnines/cmon-proxy/rpcserver/session"

	"go.uber.org/zap"
)

type SessionData struct {
	User  *config.ProxyUser
	Login time.Time
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

func cleanupOldSessions() {
	sesssMtx.Lock()
	defer sesssMtx.Unlock()

	invalidate := make([]string, 0)
	// collect the outdated logins
	for sessionId, data := range sesss {
		if time.Since(data.Login) > session.SessionTTL {
			invalidate = append(invalidate, sessionId)

			// audit log of server side logouts
			if data.User != nil {
				zap.L().Info(
					fmt.Sprintf("[AUDIT] Logout '%s' (TTL)",
						data.User.Username))
			}
		}
	}
	// invalidate them, lets do also audit log
	for _, sessionId := range invalidate {
		delete(sesss, sessionId)
	}
}

// retrieves the ProxyUser object for the actual session
func getUserForSession(ctx *gin.Context) *config.ProxyUser {
	if ctx == nil {
		return nil
	}
	cleanupOldSessions()
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
	}
	ctx.Set(userKey, user)
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

	user, err := p.r.Config.GetUser(req.Username)
	if err != nil {
		resp.RequestStatus = cmonapi.RequestStatusAccessDenied
		resp.ErrorString = fmt.Sprintf("user error: %s", err.Error())
	}

	if user != nil {
		if err := user.ValidatePassword(req.Password); err != nil {
			resp.RequestStatus = cmonapi.RequestStatusAccessDenied
			resp.ErrorString = fmt.Sprintf("password error: %s", err.Error())
		} else {
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
	}

	var resp cmonapi.WithResponseData
	resp.RequestStatus = cmonapi.RequestStatusOk

	ctx.JSON(cmonapi.RequestStatusToStatusCode(resp.RequestStatus), resp)
}
