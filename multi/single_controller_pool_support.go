package multi

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	cmon "github.com/severalnines/cmon-proxy/cmon"
	cmonapi "github.com/severalnines/cmon-proxy/cmon/api"
	"github.com/severalnines/cmon-proxy/config"
	api "github.com/severalnines/cmon-proxy/multi/api"
	"github.com/severalnines/cmon-proxy/multi/router"
	"github.com/severalnines/cmon-proxy/poolhelpers"
)

// SingleControllerPoolSupport provides pool controller functionality for single controller mode
type SingleControllerPoolSupport struct {
	proxy *Proxy
}

// NewSingleControllerPoolSupport creates a new instance of SingleControllerPoolSupport
func NewSingleControllerPoolSupport(proxy *Proxy) *SingleControllerPoolSupport {
	return &SingleControllerPoolSupport{
		proxy: proxy,
	}
}

// getSingleControllerCachedStatus retrieves or refreshes cached status for single controller
func (s *SingleControllerPoolSupport) getSingleControllerCachedStatus(controller *config.CmonInstance, ctx *gin.Context) *api.ControllerStatus {
	addr := controller.Url
	zap.L().Sugar().Debugf("[POOL-SINGLE-CACHE] Checking cache for controller: %s", addr)
	
	cacheMtx.Lock()
	status := controllerStatusCache[addr]
	cacheMtx.Unlock()
	
	// Check if cache is valid (similar to router cache logic)
	needsRefresh := status == nil || 
		status.LastUpdated.T.IsZero() || 
		time.Since(status.LastUpdated.T) > time.Duration(60)*time.Second // Use 60s interval like PingInterval
	
	if status == nil {
		zap.L().Sugar().Debugf("[POOL-SINGLE-CACHE] No cached status found, will refresh")
	} else if status.LastUpdated.T.IsZero() {
		zap.L().Sugar().Debugf("[POOL-SINGLE-CACHE] Cache timestamp is zero, will refresh")
	} else {
		age := time.Since(status.LastUpdated.T)
		zap.L().Sugar().Debugf("[POOL-SINGLE-CACHE] Cache age: %v, needs refresh: %v", age, needsRefresh)
	}
	
	if needsRefresh {
		zap.L().Sugar().Debugf("[POOL-SINGLE-CACHE] Refreshing controller status")
		status = s.refreshSingleControllerStatus(controller, ctx)
	} else {
		zap.L().Sugar().Debugf("[POOL-SINGLE-CACHE] Using cached status")
	}
	
	return status
}

// refreshSingleControllerStatus performs ping with controllers for single controller and caches result
// Now uses router's authenticated client instead of creating temporary client
func (s *SingleControllerPoolSupport) refreshSingleControllerStatus(controller *config.CmonInstance, ctx *gin.Context) *api.ControllerStatus {
	zap.L().Sugar().Debugf("[POOL-SINGLE-REFRESH] Refreshing status for controller: %s", controller.Url)
	
	// Try to use router's authenticated client
	r := s.proxy.Router(ctx)
	var client *cmon.Client
	
	if r != nil {
		c := r.Cmon(controller.Url)
		if c != nil && c.Client != nil {
			client = c.Client
			zap.L().Sugar().Debugf("[POOL-SINGLE-REFRESH] Using authenticated client from router")
		}
	}
	
	// Fallback: create temporary client if no router available
	if client == nil {
		zap.L().Sugar().Warnf("[POOL-SINGLE-REFRESH] No router available, creating temporary client (may fail without auth)")
		timeout := s.proxy.cfg.Timeout
		if timeout <= 0 {
			timeout = 30
		}
		client = cmon.NewClient(controller, timeout)
		
		// Try to get session from router if available
		if r != nil {
			c := r.Cmon(controller.Url)
			if c != nil && c.Client != nil {
				if sess := c.Client.GetSessionCookie(); sess != nil {
					client.SetSessionCookie(sess)
					zap.L().Sugar().Debugf("[POOL-SINGLE-REFRESH] Using session cookie from router")
				}
			}
		}
	}
	
	// Use PingWithControllers to get both ping and pool controllers info
	zap.L().Sugar().Debugf("[POOL-SINGLE-REFRESH] Executing PingWithControllers")
	pingResp, controllers, err := client.PingWithControllers()
	
	status := &api.ControllerStatus{
		Url:           controller.Url,
		Name:          truncateControllerName(controller.Name),
		ControllerID:  controller.Xid,
		Xid:           controller.Xid,
		FrontendUrl:   controller.FrontendUrl,
		LastUpdated:   cmonapi.NullTime{T: time.Now()},
		Controllers:   controllers, // This is the key - pool controllers info
	}
	
	if err != nil {
		zap.L().Sugar().Errorf("[POOL-SINGLE-REFRESH] PingWithControllers failed: %v", err)
		
		// Check if this is an authentication error - don't cache these failures
		errStr := err.Error()
		if strings.Contains(errStr, "no password or keyfile is defined") ||
		   strings.Contains(errStr, "authentication") ||
		   strings.Contains(errStr, "unauthorized") ||
		   strings.Contains(errStr, "access denied") {
			zap.L().Sugar().Warnf("[POOL-SINGLE-REFRESH] Authentication error detected, not caching failure: %v", err)
			
			// Return a temporary status that indicates auth failure but don't cache it
			return &api.ControllerStatus{
				Url:           controller.Url,
				Name:          truncateControllerName(controller.Name),
				ControllerID:  controller.Xid,
				Xid:           controller.Xid,
				FrontendUrl:   controller.FrontendUrl,
				Status:        api.Failed,
				StatusMessage: "Authentication required - not cached",
				LastUpdated:   cmonapi.NullTime{T: time.Now()},
				Controllers:   []*cmonapi.PoolController{}, // Empty pool controllers
			}
		}
		
		// For other types of errors, we can cache them normally
		status.Status = api.Failed
		status.StatusMessage = err.Error()
	} else {
		zap.L().Sugar().Debugf("[POOL-SINGLE-REFRESH] PingWithControllers successful, found %d pool controllers", len(controllers))
		for i, ctrl := range controllers {
			zap.L().Sugar().Debugf("[POOL-SINGLE-REFRESH] Pool controller %d: %s:%d status=%s clusters=%v", i, ctrl.Hostname, ctrl.Port, ctrl.Status, ctrl.Clusters)
		}
		
		status.Status = api.Ok
		status.LastSeen = cmonapi.NullTime{T: time.Now()}
		
		if pingResp != nil && len(pingResp.Version) > 0 {
			status.Version = pingResp.Version
		} else if len(client.ServerVersion()) > 0 {
			status.Version = client.ServerVersion()
		}
	}
	
	// Persist in cache (only if it's not an auth failure)
	zap.L().Sugar().Debugf("[POOL-SINGLE-REFRESH] Caching status for: %s", controller.Url)
	cacheMtx.Lock()
	controllerStatusCache[controller.Url] = status
	cacheMtx.Unlock()
	
	return status
}

// filterActivePoolControllers returns only active targets with valid hostname and port
func (s *SingleControllerPoolSupport) filterActivePoolControllers(controllers []*cmonapi.PoolController) []*cmonapi.PoolController {
	return poolhelpers.FilterActivePoolControllers(controllers)
}


// HandleRequest is the main entry point for single controller requests with pool controller support
// This extends the original PRCProxySingleController to support smart routing across pool controllers
func (s *SingleControllerPoolSupport) HandleRequest(ctx *gin.Context) {
	zap.L().Sugar().Debugf("[POOL-SINGLE] Request received: %s %s", ctx.Request.Method, ctx.Request.URL.Path)
	
	resp := &cmonapi.WithResponseData{
		RequestProcessed: cmonapi.NullTime{T: time.Now()},
		RequestStatus:    cmonapi.RequestStatusOk,
		ErrorString:      "",
	}

	if s.proxy.cfg.SingleController == "" {
		zap.L().Sugar().Warnf("[POOL-SINGLE] Single controller is not defined")
		resp.RequestStatus = cmonapi.RequestStatusUnknownError
		resp.ErrorString = "Single controller is not defined"
		ctx.JSON(cmonapi.RequestStatusToStatusCode(resp.RequestStatus), resp)
		return
	}
	
	zap.L().Sugar().Debugf("[POOL-SINGLE] Using single controller: %s", s.proxy.cfg.SingleController)

	controller := s.proxy.cfg.ControllerById(s.proxy.cfg.SingleController)
	if controller == nil {
		zap.L().Sugar().Errorf("[POOL-SINGLE] Single controller not found: %s", s.proxy.cfg.SingleController)
		resp.RequestStatus = cmonapi.RequestStatusUnknownError
		resp.ErrorString = "Single controller not found"
		ctx.JSON(cmonapi.RequestStatusToStatusCode(resp.RequestStatus), resp)
		return
	}
	
		zap.L().Sugar().Debugf("[POOL-SINGLE] Controller found: %s (URL: %s)", controller.Name, controller.Url)

	// Read request body for smart routing analysis
	var bodyBytes []byte
	if ctx.Request.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(ctx.Request.Body)
		if err != nil {
			resp.RequestStatus = cmonapi.RequestStatusUnknownError
			resp.ErrorString = "Failed to read request body"
			ctx.JSON(cmonapi.RequestStatusToStatusCode(resp.RequestStatus), resp)
			return
		}
		// Restore body for potential fallback
		ctx.Request.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	// Check if this is an authentication request
	if strings.Contains(ctx.Request.URL.Path, "/auth") {
		var authReq map[string]interface{}
		if err := json.Unmarshal(bodyBytes, &authReq); err == nil {
			if operation, ok := authReq["operation"].(string); ok && operation == "authenticateWithPassword" {
				// Extract username and password
				username, _ := authReq["user_name"].(string)
				password, _ := authReq["password"].(string)
				
				if username != "" && password != "" {
					zap.L().Sugar().Infof("[SINGLE-AUTH] Intercepting authentication request for user: %s", username)
					
					// Authenticate using single controller login
					_, err := s.proxy.singleControllerLogin(ctx, username, password)
					if err != nil {
						zap.L().Sugar().Warnf("[SINGLE-AUTH] Authentication failed: %v", err)
						// Fall through to proxy the request (let cmon handle the error)
					} else {
						zap.L().Sugar().Infof("[SINGLE-AUTH] Authentication successful for user: %s", username)
						
						// Ensure session is saved before returning response
						session := sessions.Default(ctx)
						if err := session.Save(); err != nil {
							zap.L().Sugar().Errorf("[SINGLE-AUTH] Failed to save session: %v", err)
						}
						
						// Now proxy the request to cmon, but use the router's client instead
						// This ensures we use the authenticated session
						r := s.proxy.Router(ctx)
						if r != nil {
							controller := s.proxy.cfg.ControllerById(s.proxy.cfg.SingleController)
							if controller != nil {
								c := r.Cmon(controller.Url)
								if c != nil && c.Client != nil {
									// Extract the actual path (remove /single prefix if present)
									requestPath := ctx.Request.URL.EscapedPath()
									if strings.HasPrefix(requestPath, "/single") {
										requestPath = strings.TrimPrefix(requestPath, "/single")
									}
									
									// Use the router's authenticated client to make the request
									resBytes, err := c.Client.RequestBytes(requestPath, bodyBytes, false)
									if err == nil {
										ctx.Data(http.StatusOK, "application/json", resBytes)
										return
									}
									zap.L().Sugar().Warnf("[SINGLE-AUTH] Request failed, falling back to proxy: %v", err)
								}
							}
						}
						// Fall through to proxy if router request fails
					}
				}
			}
		}
	}

	// Check if user is authenticated - required for smart routing
	// If not authenticated, return auth required (same as PRCProxySingleController)
	if user := getUserForSession(ctx); user == nil {
		zap.L().Sugar().Debugf("[POOL-SINGLE] No authenticated user found, returning auth required")
		resp.RequestStatus = cmonapi.RequestStatusAuthRequired
		resp.ErrorString = "Authentication required"
		ctx.JSON(cmonapi.RequestStatusToStatusCode(resp.RequestStatus), resp)
		return
	}

	// Get cached status with pool controllers info
	zap.L().Sugar().Debugf("[POOL-SINGLE] Getting cached status for controller")
	status := s.getSingleControllerCachedStatus(controller, ctx)
	
	zap.L().Sugar().Debugf("[POOL-SINGLE] Controller status: %s, Pool controllers found: %d", status.Status, len(status.Controllers))
	
	// Try smart routing across pool controllers if available
	if len(status.Controllers) > 0 {
		zap.L().Sugar().Debugf("[POOL-SINGLE] Found %d pool controllers, filtering active ones", len(status.Controllers))
		activeTargets := s.filterActivePoolControllers(status.Controllers)
		zap.L().Sugar().Debugf("[POOL-SINGLE] Active pool controllers: %d", len(activeTargets))
		
		if len(activeTargets) > 0 {
			// Log active targets details
			for i, target := range activeTargets {
				zap.L().Sugar().Debugf("[POOL-SINGLE] Active target %d: %s:%d (clusters: %v)", i, target.Hostname, target.Port, target.Clusters)
			}
			
			// Try smart routing - if successful, it will write response and return true
			zap.L().Sugar().Debugf("[POOL-SINGLE] Attempting smart routing with %d active targets", len(activeTargets))
			if s.trySmartRouteAcrossPoolForSingle(ctx, bodyBytes, activeTargets, controller) {
				zap.L().Sugar().Debugf("[POOL-SINGLE] Smart routing successful, response sent")
				return
			}
			zap.L().Sugar().Debugf("[POOL-SINGLE] Smart routing did not handle request, falling back")
		} else {
			zap.L().Sugar().Debugf("[POOL-SINGLE] No active pool controllers found")
		}
	} else {
		zap.L().Sugar().Debugf("[POOL-SINGLE] No pool controllers found in status")
	}

	// Fallback to original single controller behavior
	zap.L().Sugar().Debugf("[POOL-SINGLE] Falling back to original single controller behavior")
	s.proxy.PRCProxySingleController(ctx)
}

// trySmartRouteAcrossPoolForSingle performs smart routing for single controller mode
// Uses the same aggregation and smart routing logic as multicontroller
// Requires authenticated user session - returns false if user is not authenticated
func (s *SingleControllerPoolSupport) trySmartRouteAcrossPoolForSingle(
	ctx *gin.Context,
	jsonData []byte,
	activeTargets []*cmonapi.PoolController,
	controllerInstance *config.CmonInstance,
) bool {
	zap.L().Sugar().Debugf("[POOL-SINGLE-ROUTING] Starting smart routing with %d targets", len(activeTargets))
	if len(activeTargets) < 1 { 
		zap.L().Sugar().Debugf("[POOL-SINGLE-ROUTING] No active targets, returning false")
		return false 
	}

	// Check if user is authenticated - if not, we can't proceed with smart routing
	// The caller should return RequestStatusAuthRequired instead
	if user := getUserForSession(ctx); user == nil {
		zap.L().Sugar().Debugf("[POOL-SINGLE-ROUTING] No authenticated user found, cannot perform smart routing")
		return false
	}

	// Get router - should always exist if user is authenticated
	var r *router.Router
	r = s.proxy.Router(ctx)
	if r == nil {
		zap.L().Sugar().Warnf("[POOL-SINGLE-ROUTING] Router is nil even though user is authenticated - this should not happen")
		return false
	}

	// Get controller ID from router
	var controllerId string
	for _, addr := range r.Urls() {
		c := r.Cmon(addr)
		if c != nil && c.Client != nil && c.Client.Instance != nil {
			if c.Client.Instance.Xid == controllerInstance.Xid || c.Client.Instance.Url == controllerInstance.Url {
				controllerId = c.Xid()
				if controllerId == "" {
					controllerId = c.PoolID()
				}
				break
			}
		}
	}
	if controllerId == "" {
		controllerId = controllerInstance.Xid
	}

	zap.L().Sugar().Debugf("[POOL-SINGLE-ROUTING] Using router-based smart routing with controllerId: %s", controllerId)
	
	// Helper to remove /single prefix from path (single mode uses /single/v2/* paths)
	getRequestPath := func() string {
		requestPath := ctx.Request.URL.EscapedPath()
		if strings.HasPrefix(requestPath, "/single") {
			requestPath = strings.TrimPrefix(requestPath, "/single")
		}
		return requestPath
	}
	
	// Use the same smart routing logic as multicontroler by delegating to poolhelpers functions
	return poolhelpers.TrySmartRouteAcrossPool(ctx, controllerId, jsonData, activeTargets, r, getRequestPath)
}

