package multi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	cmon "github.com/severalnines/cmon-proxy/cmon"
	cmonapi "github.com/severalnines/cmon-proxy/cmon/api"
	"github.com/severalnines/cmon-proxy/config"
	api "github.com/severalnines/cmon-proxy/multi/api"
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
	
	mtx.Lock()
	status := controllerStatusCache[addr]
	mtx.Unlock()
	
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
func (s *SingleControllerPoolSupport) refreshSingleControllerStatus(controller *config.CmonInstance, ctx *gin.Context) *api.ControllerStatus {
	timeout := s.proxy.cfg.Timeout
	if timeout <= 0 {
		timeout = 30
	}
	
	zap.L().Sugar().Debugf("[POOL-SINGLE-REFRESH] Creating client for controller: %s (timeout: %d)", controller.Url, timeout)
	client := cmon.NewClient(controller, timeout)
	
	// Extract and set cookies from the request for authentication
	if ctx.Request.Header.Get("Cookie") != "" {
		zap.L().Sugar().Debugf("[POOL-SINGLE-REFRESH] Setting authentication cookies from request")
		// Parse cookies from request
		cookies := ctx.Request.Cookies()
		for _, cookie := range cookies {
			zap.L().Sugar().Debugf("[POOL-SINGLE-REFRESH] Setting cookie: %s", cookie.Name)
			if cookie.Name == "cmon-sid" { // Only set the session cookie
				client.SetSessionCookie(cookie)
				break
			}
		}
	} else {
		zap.L().Sugar().Warnf("[POOL-SINGLE-REFRESH] No cookies found in request - authentication may fail")
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
	mtx.Lock()
	controllerStatusCache[controller.Url] = status
	mtx.Unlock()
	
	return status
}

// filterActivePoolControllers returns only active targets with valid hostname and port
func (s *SingleControllerPoolSupport) filterActivePoolControllers(controllers []*cmonapi.PoolController) []*cmonapi.PoolController {
	active := make([]*cmonapi.PoolController, 0, len(controllers))
	for _, pc := range controllers {
		if strings.EqualFold(pc.Status, "active") && pc.Hostname != "" && pc.Port > 0 {
			active = append(active, pc)
		}
	}
	return active
}

// extractModuleFromPath extracts the module name from a request path
// For example: "/single/v2/tree" -> "tree", "/single/v2/clusters" -> "clusters"
func (s *SingleControllerPoolSupport) extractModuleFromPath(path string) string {
	// Remove leading slash if present
	cleanPath := strings.TrimPrefix(path, "/")
	
	// Split by "/" and look for the module after "v2"
	parts := strings.Split(cleanPath, "/")
	
	// Expected format: single/v2/module or v2/module
	for i, part := range parts {
		if part == "v2" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	
	// Fallback: if no "v2" found, use the last part
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	
	// Default fallback
	return "info"
}

// parsePaginationParams extracts pagination parameters from request JSON
func (s *SingleControllerPoolSupport) parsePaginationParams(jsonData []byte) (ascending bool, limit int, offset int) {
	var bodyMap map[string]interface{}
	if json.Unmarshal(jsonData, &bodyMap) != nil {
		return false, 0, 0
	}
	
	// Extract ascending
	if asc, ok := bodyMap["ascending"].(bool); ok {
		ascending = asc
	}
	
	// Extract limit
	if l, ok := bodyMap["limit"].(float64); ok {
		limit = int(l)
	}
	
	// Extract offset
	if o, ok := bodyMap["offset"].(float64); ok {
		offset = int(o)
	}
	
	return ascending, limit, offset
}

// removePaginationParams removes pagination parameters from request JSON
// This is needed for getJobInstances and similar operations where pagination 
// is handled by the aggregation layer, not the individual pool controllers
func (s *SingleControllerPoolSupport) removePaginationParams(jsonData []byte) []byte {
	var bodyMap map[string]interface{}
	if json.Unmarshal(jsonData, &bodyMap) != nil {
		return jsonData // Return original if we can't parse
	}
	
	// Remove pagination parameters
	delete(bodyMap, "limit")
	delete(bodyMap, "offset") 
	delete(bodyMap, "ascending")
	delete(bodyMap, "order")
	
	// Marshal back to JSON
	cleanedData, err := json.Marshal(bodyMap)
	if err != nil {
		return jsonData // Return original if marshal fails
	}
	
	return cleanedData
}

// extractStandardTimestamp extracts timestamp from items with standard timestamp fields
// This replaces extractJobTimestamp, extractAlarmTimestamp, and extractGenericTimestamp
func (s *SingleControllerPoolSupport) extractStandardTimestamp(item map[string]interface{}) time.Time {
	for _, key := range []string{"created", "created_time", "created_ts"} {
		if s, ok := item[key].(string); ok {
			if t, err := time.Parse(time.RFC3339, s); err == nil {
				return t
			}
		}
	}
	return time.Time{}
}

// extractBackupTimestamp extracts timestamp from backup items for sorting
func (s *SingleControllerPoolSupport) extractBackupTimestamp(item map[string]interface{}) time.Time {
	if md, ok := item["metadata"].(map[string]interface{}); ok {
		if s, ok := md["created"].(string); ok {
			if t, err := time.Parse(time.RFC3339, s); err == nil {
				return t
			}
		}
	}
	return time.Time{}
}


// aggregateTreeAcrossPoolForSingle performs tree aggregation for single controller mode
// This implements the same logic as the multi-controller tree aggregation
func (s *SingleControllerPoolSupport) aggregateTreeAcrossPoolForSingle(
	ctx *gin.Context,
	jsonData []byte,
	activeTargets []*cmonapi.PoolController,
	controllerInstance *config.CmonInstance,
) bool {
	zap.L().Sugar().Debugf("[POOL-SINGLE-TREE] Starting tree aggregation with %d targets", len(activeTargets))
	
	// Prepare aggregation containers (same as multi-controller)
	var baseResp map[string]interface{}
	baseNonCluster := make([]interface{}, 0)
	clusterItems := make([]interface{}, 0)
	seenClusters := make(map[string]bool) // Deduplication map for clusters
	
	// Channel and sync for parallel requests
	type treeResponse struct {
		response map[string]interface{}
		target   *cmonapi.PoolController
		err      error
	}
	
	responseChan := make(chan treeResponse, len(activeTargets))
	var wg sync.WaitGroup

	// Extract module from request path
	requestPath := ctx.Request.URL.EscapedPath()
	module := s.extractModuleFromPath(requestPath)

	// Request each active pool controller in parallel
	for _, target := range activeTargets {
		wg.Add(1)
		go func(target *cmonapi.PoolController) {
			defer wg.Done()
			
			instCopy := *controllerInstance
			instCopy.Url = target.Hostname + ":" + strconv.Itoa(target.Port+1)
			timeout := s.proxy.cfg.Timeout
			if timeout <= 0 { timeout = 30 }
			tmpClient := cmon.NewClient(&instCopy, timeout)
			
			// Set authentication cookies
			if ctx.Request.Header.Get("Cookie") != "" {
				cookies := ctx.Request.Cookies()
				for _, cookie := range cookies {
					if cookie.Name == "cmon-sid" {
						tmpClient.SetSessionCookie(cookie)
						break
					}
				}
			}
			
			zap.L().Sugar().Debugf("[POOL-SINGLE-TREE] Requesting module: %s from %s:%d", module, target.Hostname, target.Port)
			resBytes, err := tmpClient.RequestBytes(module, jsonData, false)
			if err != nil {
				zap.L().Sugar().Warnf("[POOL-SINGLE-TREE] poolcontroller %s:%d tree request error: %v", target.Hostname, target.Port, err)
				responseChan <- treeResponse{nil, target, err}
				return
			}
			
			var respMap map[string]interface{}
			if err := json.Unmarshal(resBytes, &respMap); err != nil {
				zap.L().Sugar().Warnf("[POOL-SINGLE-TREE] poolcontroller %s:%d tree invalid response: %v", target.Hostname, target.Port, err)
				responseChan <- treeResponse{nil, target, err}
				return
			}
			
			responseChan <- treeResponse{respMap, target, nil}
		}(target)
	}

	// Wait for all requests to complete
	wg.Wait()
	close(responseChan)

	// Process responses sequentially for consistent baseResp and deduplication
	for resp := range responseChan {
		if resp.err != nil || resp.response == nil {
			continue
		}

		// Initialize base response and capture non-cluster items from the first success
		if baseResp == nil {
			baseResp = resp.response
			if cdt, ok := baseResp["cdt"].(map[string]interface{}); ok {
				if subs, ok := cdt["sub_items"].([]interface{}); ok {
					zap.L().Sugar().Debugf("[POOL-SINGLE-TREE] Processing %d sub_items from base response", len(subs))
					for _, it := range subs {
						m, _ := it.(map[string]interface{})
						if m == nil { continue }
						if t, _ := m["item_type"].(string); !strings.EqualFold(t, "Cluster") { 
							baseNonCluster = append(baseNonCluster, it) 
						}
					}
				}
			}
		}

		// From each response collect cluster items with deduplication
		if cdt, ok := resp.response["cdt"].(map[string]interface{}); ok {
			if subs, ok := cdt["sub_items"].([]interface{}); ok {
				for _, it := range subs {
					m, _ := it.(map[string]interface{})
					if m == nil { continue }
					if t, _ := m["item_type"].(string); strings.EqualFold(t, "Cluster") {
						// Use cluster_id for deduplication
						if id, ok := m["cluster_id"]; ok {
							clusterKey := fmt.Sprintf("%v", id)
							// Only add if not seen before
							if !seenClusters[clusterKey] {
								seenClusters[clusterKey] = true
								clusterItems = append(clusterItems, it)
								zap.L().Sugar().Debugf("[POOL-SINGLE-TREE] Added cluster %s from %s:%d", clusterKey, resp.target.Hostname, resp.target.Port)
							} else {
								zap.L().Sugar().Debugf("[POOL-SINGLE-TREE] Skipping duplicate cluster %s from %s:%d", clusterKey, resp.target.Hostname, resp.target.Port)
							}
						}
					}
				}
			}
		}
	}

	// If we couldn't build a base response, return false to fall back
	if baseResp == nil {
		zap.L().Sugar().Warnf("[POOL-SINGLE-TREE] No successful responses, falling back")
		return false
	}

	// Merge: non-cluster from base + all clusters from all controllers
	if cdt, ok := baseResp["cdt"].(map[string]interface{}); ok {
		merged := make([]interface{}, 0, len(baseNonCluster)+len(clusterItems))
		merged = append(merged, baseNonCluster...)
		merged = append(merged, clusterItems...)
		cdt["sub_items"] = merged
		zap.L().Sugar().Debugf("[POOL-SINGLE-TREE] Tree aggregation complete: %d non-cluster + %d cluster items = %d total", len(baseNonCluster), len(clusterItems), len(merged))
	}
	
	ctx.JSON(http.StatusOK, baseResp)
	return true
}

// aggregateListAcrossPoolForSingle performs list aggregation for single controller mode
func (s *SingleControllerPoolSupport) aggregateListAcrossPoolForSingle(
	ctx *gin.Context,
	jsonData []byte,
	activeTargets []*cmonapi.PoolController,
	controllerInstance *config.CmonInstance,
	listKeys []string,
	tsExtractor func(map[string]interface{}) time.Time,
	ascending bool,
	limit int,
	offset int,
) bool {
	if len(activeTargets) == 0 {
		return false
	}

	zap.L().Sugar().Debugf("[POOL-SINGLE-LIST] Starting list aggregation for keys: %v", listKeys)

	// Channel to collect responses from parallel requests
	type poolResponse struct {
		response map[string]interface{}
		target   *cmonapi.PoolController
		err      error
	}

	responseChan := make(chan poolResponse, len(activeTargets))
	var wg sync.WaitGroup

	// Extract module from request path
	requestPath := ctx.Request.URL.EscapedPath()
	module := s.extractModuleFromPath(requestPath)

	// Launch parallel requests to all pool controllers
	for _, target := range activeTargets {
		wg.Add(1)
		go func(target *cmonapi.PoolController) {
			defer wg.Done()
			
			instCopy := *controllerInstance
			instCopy.Url = target.Hostname + ":" + strconv.Itoa(target.Port+1)
			timeout := s.proxy.cfg.Timeout
			if timeout <= 0 { timeout = 30 }
			tmpClient := cmon.NewClient(&instCopy, timeout)
			
			// Set authentication cookies
			if ctx.Request.Header.Get("Cookie") != "" {
				cookies := ctx.Request.Cookies()
				for _, cookie := range cookies {
					if cookie.Name == "cmon-sid" {
						tmpClient.SetSessionCookie(cookie)
						break
					}
				}
			}
			
			zap.L().Sugar().Debugf("[POOL-SINGLE-LIST] Requesting module: %s from %s:%d", module, target.Hostname, target.Port)
			resBytes, err := tmpClient.RequestBytes(module, jsonData, false)
			
			resp := poolResponse{target: target, err: err}
			if err == nil {
				_ = json.Unmarshal(resBytes, &resp.response)
			}
			responseChan <- resp
		}(target)
	}

	// Wait for all requests to complete
	go func() {
		wg.Wait()
		close(responseChan)
	}()

	// Collect and process responses
	var baseResp map[string]interface{}
	var allItems []interface{}
	
	for resp := range responseChan {
		if resp.err != nil {
			zap.L().Sugar().Errorf("[POOL-SINGLE-LIST] Error from %s:%d: %v", resp.target.Hostname, resp.target.Port, resp.err)
			continue
		}
		
		if resp.response == nil {
			continue
		}
		
		// Use first successful response as base structure
		if baseResp == nil {
			baseResp = resp.response
		}
		
		// Extract items from list keys
		for _, key := range listKeys {
			if items, ok := resp.response[key].([]interface{}); ok {
				allItems = append(allItems, items...)
			}
		}
	}
	
	if baseResp == nil {
		zap.L().Sugar().Warnf("[POOL-SINGLE-LIST] No successful responses")
		return false
	}
	
	// Sort items if timestamp extractor is provided
	if tsExtractor != nil && len(allItems) > 0 {
		sort.Slice(allItems, func(i, j int) bool {
			iMap, iOk := allItems[i].(map[string]interface{})
			jMap, jOk := allItems[j].(map[string]interface{})
			if !iOk || !jOk {
				return false
			}
			
			iTime := tsExtractor(iMap)
			jTime := tsExtractor(jMap)
			
			if ascending {
				return iTime.Before(jTime)
			}
			return iTime.After(jTime)
		})
	}
	
	// Apply pagination
	total := len(allItems)
	start := offset
	if start > total {
		start = total
	}
	
	end := start + limit
	if limit <= 0 || end > total {
		end = total
	}
	
	if start < end {
		allItems = allItems[start:end]
	} else {
		allItems = []interface{}{}
	}
	
	// Update base response with aggregated and paginated items
	for _, key := range listKeys {
		baseResp[key] = allItems
	}
	baseResp["total"] = int64(total)
	
	zap.L().Sugar().Debugf("[POOL-SINGLE-LIST] Aggregated %d items, returning %d items (offset:%d, limit:%d)", total, len(allItems), offset, limit)
	ctx.JSON(http.StatusOK, baseResp)
	return true
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
// Note: This is a simplified version that focuses on aggregation endpoints
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

	// Parse request to get operation and cluster_id
	var bodyMap map[string]interface{}
	_ = json.Unmarshal(jsonData, &bodyMap)
	var op string
	var clusterID string
	if bodyMap != nil {
		op, _ = bodyMap["operation"].(string)
		if cid, ok := bodyMap["cluster_id"]; ok {
			clusterID = fmt.Sprintf("%v", cid)
		}
		zap.L().Sugar().Debugf("[POOL-SINGLE-ROUTING] Request operation: %s, cluster_id: %s", op, clusterID)
	}

	// Check for cluster-specific routing first
	if clusterID != "" {
			zap.L().Sugar().Debugf("[POOL-SINGLE-ROUTING] Cluster-specific request detected for cluster_id: %s", clusterID)
		if target := s.findPoolControllerForCluster(clusterID, activeTargets); target != nil {
				zap.L().Sugar().Debugf("[POOL-SINGLE-ROUTING] Found target pool controller %s:%d for cluster %s", target.Hostname, target.Port, clusterID)
			return s.routeToSpecificPoolController(ctx, jsonData, target, controllerInstance)
		} else {
			zap.L().Sugar().Warnf("[POOL-SINGLE-ROUTING] No pool controller found for cluster_id: %s, will try aggregation or fallback", clusterID)
		}
	}

	// Aggregation endpoints for single controller mode
	requestPath := ctx.Request.URL.Path
	
	// Tree aggregation endpoint
	if strings.Contains(requestPath, "/tree") {
		zap.L().Sugar().Debugf("[POOL-SINGLE-ROUTING] Request path contains /tree, checking for getTree operation")
		var withOp cmonapi.WithOperation
		_ = json.Unmarshal(jsonData, &withOp)
		if strings.EqualFold(withOp.Operation, "getTree") {
			zap.L().Sugar().Debugf("[POOL-SINGLE-ROUTING] getTree operation detected, performing tree aggregation")
			return s.aggregateTreeAcrossPoolForSingle(ctx, jsonData, activeTargets, controllerInstance)
		} else {
			zap.L().Sugar().Debugf("[POOL-SINGLE-ROUTING] Tree path but operation is: %s", withOp.Operation)
		}
	}
	
	// Clusters aggregation endpoint
	if strings.Contains(requestPath, "/clusters") {
		zap.L().Sugar().Debugf("[POOL-SINGLE-ROUTING] Request path contains /clusters, checking for getAllClusterInfo operation")
		var withOp cmonapi.WithOperation
		_ = json.Unmarshal(jsonData, &withOp)
		if strings.EqualFold(withOp.Operation, "getAllClusterInfo") {
			zap.L().Sugar().Debugf("[POOL-SINGLE-ROUTING] getAllClusterInfo operation detected, performing clusters aggregation")
			return s.aggregateListAcrossPoolForSingle(ctx, jsonData, activeTargets, controllerInstance, []string{"clusters"}, nil, false, 0, 0)
		}
	}
	
	// Jobs aggregation endpoint
	if strings.Contains(requestPath, "/jobs") {
		zap.L().Sugar().Debugf("[POOL-SINGLE-ROUTING] Request path contains /jobs, checking for job operations")
		var withOp cmonapi.WithOperation
		_ = json.Unmarshal(jsonData, &withOp)
		if strings.EqualFold(withOp.Operation, "getJobs") {
			zap.L().Sugar().Debugf("[POOL-SINGLE-ROUTING] getJobs operation detected, performing jobs aggregation")
			// Parse pagination parameters and clean them from request
			ascending, limit, offset := s.parsePaginationParams(jsonData)
			cleanedData := s.removePaginationParams(jsonData)
			return s.aggregateListAcrossPoolForSingle(ctx, cleanedData, activeTargets, controllerInstance, []string{"jobs"}, s.extractStandardTimestamp, ascending, limit, offset)
		} else if strings.EqualFold(withOp.Operation, "getJobInstances") {
			zap.L().Sugar().Debugf("[POOL-SINGLE-ROUTING] getJobInstances operation detected, performing job instances aggregation")
			// Parse pagination parameters and clean them from request (like in original implementation)
			ascending, limit, offset := s.parsePaginationParams(jsonData)
			cleanedData := s.removePaginationParams(jsonData)
			return s.aggregateListAcrossPoolForSingle(ctx, cleanedData, activeTargets, controllerInstance, []string{"jobs"}, s.extractStandardTimestamp, ascending, limit, offset)
		}
	}
	
	// Backup aggregation endpoint
	if strings.Contains(requestPath, "/backup") {
		zap.L().Sugar().Debugf("[POOL-SINGLE-ROUTING] Request path contains /backup, checking for getBackups operation")
		var withOp cmonapi.WithOperation
		_ = json.Unmarshal(jsonData, &withOp)
		if strings.EqualFold(withOp.Operation, "getBackups") {
			zap.L().Sugar().Debugf("[POOL-SINGLE-ROUTING] getBackups operation detected, performing backup aggregation")
			// Parse pagination parameters and clean them from request
			ascending, limit, offset := s.parsePaginationParams(jsonData)
			cleanedData := s.removePaginationParams(jsonData)
			return s.aggregateListAcrossPoolForSingle(ctx, cleanedData, activeTargets, controllerInstance, []string{"backup_records"}, s.extractBackupTimestamp, ascending, limit, offset)
		}
	}
	
	// Alarms aggregation endpoint
	if strings.Contains(requestPath, "/alarm") {
		zap.L().Sugar().Debugf("[POOL-SINGLE-ROUTING] Request path contains /alarm, checking for getAlarms operation")
		var withOp cmonapi.WithOperation
		_ = json.Unmarshal(jsonData, &withOp)
		if strings.EqualFold(withOp.Operation, "getAlarms") {
			zap.L().Sugar().Debugf("[POOL-SINGLE-ROUTING] getAlarms operation detected, performing alarms aggregation")
			// Parse pagination parameters and clean them from request
			ascending, limit, offset := s.parsePaginationParams(jsonData)
			cleanedData := s.removePaginationParams(jsonData)
			return s.aggregateListAcrossPoolForSingle(ctx, cleanedData, activeTargets, controllerInstance, []string{"alarms"}, s.extractStandardTimestamp, ascending, limit, offset)
		}
	}
	
	// Reports and other aggregation endpoints
	if strings.Contains(requestPath, "/reports") || strings.Contains(requestPath, "/audit") || strings.Contains(requestPath, "/maintenance") {
		zap.L().Sugar().Debugf("[POOL-SINGLE-ROUTING] Request path contains aggregatable endpoint: %s", requestPath)
		var withOp cmonapi.WithOperation
		_ = json.Unmarshal(jsonData, &withOp)
		
		// Handle multiple operations that use similar aggregation pattern
		if strings.EqualFold(withOp.Operation, "getReports") {
			zap.L().Sugar().Debugf("[POOL-SINGLE-ROUTING] getReports operation detected, performing reports aggregation")
			ascending, limit, offset := s.parsePaginationParams(jsonData)
			cleanedData := s.removePaginationParams(jsonData)
			return s.aggregateListAcrossPoolForSingle(ctx, cleanedData, activeTargets, controllerInstance, []string{"reports"}, s.extractStandardTimestamp, ascending, limit, offset)
		} else if strings.EqualFold(withOp.Operation, "getEntries") {
			zap.L().Sugar().Debugf("[POOL-SINGLE-ROUTING] getEntries operation detected, performing audit entries aggregation")
			ascending, limit, offset := s.parsePaginationParams(jsonData)
			cleanedData := s.removePaginationParams(jsonData)
			return s.aggregateListAcrossPoolForSingle(ctx, cleanedData, activeTargets, controllerInstance, []string{"audit_entries"}, s.extractStandardTimestamp, ascending, limit, offset)
		} else if strings.EqualFold(withOp.Operation, "getMaintenance") {
			zap.L().Sugar().Debugf("[POOL-SINGLE-ROUTING] getMaintenance operation detected, performing maintenance aggregation")
			ascending, limit, offset := s.parsePaginationParams(jsonData)
			cleanedData := s.removePaginationParams(jsonData)
			return s.aggregateListAcrossPoolForSingle(ctx, cleanedData, activeTargets, controllerInstance, []string{"maintenance_records"}, s.extractStandardTimestamp, ascending, limit, offset)
		}
	}

	zap.L().Sugar().Debugf("[POOL-SINGLE-ROUTING] No special routing applied, returning false")
	return false
}

// findPoolControllerForCluster finds the pool controller that hosts the specified cluster
func (s *SingleControllerPoolSupport) findPoolControllerForCluster(clusterID string, activeTargets []*cmonapi.PoolController) *cmonapi.PoolController {
	for _, target := range activeTargets {
		if target.Clusters == nil {
			continue
		}
		for _, cid := range target.Clusters {
			if cid == clusterID {
				zap.L().Sugar().Debugf("[POOL-SINGLE-ROUTING] Found cluster %s on pool controller %s:%d", clusterID, target.Hostname, target.Port)
				return target
			}
		}
	}
	zap.L().Sugar().Debugf("[POOL-SINGLE-ROUTING] Cluster %s not found on any pool controller", clusterID)
	return nil
}

// routeToSpecificPoolController routes a request to a specific pool controller
func (s *SingleControllerPoolSupport) routeToSpecificPoolController(
	ctx *gin.Context,
	jsonData []byte,
	target *cmonapi.PoolController,
	controllerInstance *config.CmonInstance,
) bool {
	zap.L().Sugar().Debugf("[POOL-SINGLE-SPECIFIC] Routing request to pool controller %s:%d", target.Hostname, target.Port)
	
	// Create a client for the specific pool controller
	instCopy := *controllerInstance
	instCopy.Url = target.Hostname + ":" + strconv.Itoa(target.Port+1)
	timeout := s.proxy.cfg.Timeout
	if timeout <= 0 {
		timeout = 30
	}
	tmpClient := cmon.NewClient(&instCopy, timeout)
	
	// Set authentication cookies
	if ctx.Request.Header.Get("Cookie") != "" {
		cookies := ctx.Request.Cookies()
		for _, cookie := range cookies {
			if cookie.Name == "cmon-sid" {
				tmpClient.SetSessionCookie(cookie)
				break
			}
		}
	}
	
	// Extract module from request path
	requestPath := ctx.Request.URL.EscapedPath()
	module := s.extractModuleFromPath(requestPath)
	
	zap.L().Sugar().Debugf("[POOL-SINGLE-SPECIFIC] Requesting module: %s from %s:%d", module, target.Hostname, target.Port)
	resBytes, err := tmpClient.RequestBytes(module, jsonData, false)
	if err != nil {
		zap.L().Sugar().Errorf("[POOL-SINGLE-SPECIFIC] Request to %s:%d failed: %v", target.Hostname, target.Port, err)
		return false
	}
	
	// Parse response to ensure it's valid JSON
	var respMap map[string]interface{}
	if err := json.Unmarshal(resBytes, &respMap); err != nil {
		zap.L().Sugar().Errorf("[POOL-SINGLE-SPECIFIC] Invalid JSON response from %s:%d: %v", target.Hostname, target.Port, err)
		return false
	}
	
	zap.L().Sugar().Debugf("[POOL-SINGLE-SPECIFIC] Successfully routed request to %s:%d", target.Hostname, target.Port)
	ctx.JSON(http.StatusOK, respMap)
	return true
}
