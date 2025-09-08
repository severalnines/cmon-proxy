package rpcserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/severalnines/cmon-proxy/cmon"
	cmonapi "github.com/severalnines/cmon-proxy/cmon/api"
	"github.com/severalnines/cmon-proxy/config"
	"go.uber.org/zap"
)

// filterActivePoolControllers returns only active targets with valid hostname and port.
func filterActivePoolControllers(controllers []*cmonapi.PoolController) []*cmonapi.PoolController {
	active := make([]*cmonapi.PoolController, 0, len(controllers))
	for _, pc := range controllers {
		if strings.EqualFold(pc.Status, "active") && pc.Hostname != "" && pc.Port > 0 {
			active = append(active, pc)
		}
	}
	return active
}

// trySmartRouteAcrossPool attempts to route or aggregate when there are >=1 active pool controllers.
// Returns true if it produced a response and wrote to the context.
func trySmartRouteAcrossPool(
	ctx *gin.Context,
	controllerId string,
	jsonData []byte,
	activeTargets []*cmonapi.PoolController,
) bool {
	if len(activeTargets) < 1 { return false }

	var bodyMap map[string]interface{}
	_ = json.Unmarshal(jsonData, &bodyMap)
	var (
		op string
		clusterId = -1
		clusterIdStr string
	)
	if bodyMap != nil {
		op, _ = bodyMap["operation"].(string)
		if v, ok := bodyMap["cluster_id"]; ok {
			switch t := v.(type) {
			case float64:
				clusterId = int(t)
				clusterIdStr = strconv.FormatInt(int64(t), 10)
			case string:
				clusterIdStr = t
				if n, err := strconv.Atoi(t); err == nil { clusterId = n }
			}
		}
	}

	// Helper to forward request to a specific pool-controller
	forwardTo := func(chosen *cmonapi.PoolController, warnPrefix string) bool {
		if chosen == nil { return false }
		for _, addr := range proxy.Router(ctx).Urls() {
			c := proxy.Router(ctx).Cmon(addr)
			if c == nil || c.Client == nil || !c.MatchesID(controllerId) { continue }
			instCopy := *c.Client.Instance
			instCopy.Url = chosen.Hostname + ":" + strconv.Itoa(chosen.Port+1)
			timeout := proxy.Router(ctx).Config.Timeout
			if timeout <= 0 { timeout = 10 }
			tmpClient := cmon.NewClient(&instCopy, timeout)
			if cookie := c.Client.GetSessionCookie(); cookie != nil { tmpClient.SetSessionCookie(cookie) }
			resBytes, err := tmpClient.RequestBytes(ctx.Request.URL.EscapedPath(), jsonData, false)
			if err != nil {
				zap.L().Sugar().Warnf("%s %s:%d request error: %v", warnPrefix, chosen.Hostname, chosen.Port, err)
				break
			}
			ctx.Data(http.StatusOK, "application/json", resBytes)
			return true
		}
		return false
	}

	// If multiple active pool-controllers, perform smart routing
	if len(activeTargets) > 1 {
		// Special case: createJobInstance with cluster_id=0 → choose least-loaded pool-controller
		if strings.EqualFold(op, "createJobInstance") && clusterId == 0 {
			var chosen *cmonapi.PoolController
			minClusters := 0
			for i, pc := range activeTargets {
				l := len(pc.Clusters)
				if i == 0 || l < minClusters { minClusters = l; chosen = pc }
			}
			if forwardTo(chosen, "poolcontroller createJobInstance cluster_id=0") { return true }
		}

		// If request targets a specific cluster, route directly to the controller handling it
		if clusterIdStr != "" {
			var chosen *cmonapi.PoolController
			for _, pc := range activeTargets {
				for _, cid := range pc.Clusters {
					if cid == clusterIdStr { chosen = pc; break }
				}
				if chosen != nil { break }
			}
			if forwardTo(chosen, "poolcontroller cluster-directed") { return true }
		}
	}

	// Fan-out tree aggregation: /tree with operation getTree
	if strings.Contains(ctx.Request.URL.Path, "/tree") {
		var withOp cmonapi.WithOperation
		_ = json.Unmarshal(jsonData, &withOp)
		if strings.EqualFold(withOp.Operation, "getTree") {
			for _, addr := range proxy.Router(ctx).Urls() {
				c := proxy.Router(ctx).Cmon(addr)
				if c == nil || c.Client == nil || !c.MatchesID(controllerId) { continue }

				// Prepare aggregation containers
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

				// Request each active pool controller in parallel
				for _, target := range activeTargets {
					wg.Add(1)
					go func(target *cmonapi.PoolController) {
						defer wg.Done()
						
						instCopy := *c.Client.Instance
						instCopy.Url = target.Hostname + ":" + strconv.Itoa(target.Port+1)
						timeout := proxy.Router(ctx).Config.Timeout
						if timeout <= 0 { timeout = 10 }
						tmpClient := cmon.NewClient(&instCopy, timeout)
						if cookie := c.Client.GetSessionCookie(); cookie != nil { 
							tmpClient.SetSessionCookie(cookie) 
						}
						
						resBytes, err := tmpClient.RequestBytes(ctx.Request.URL.EscapedPath(), jsonData, false)
						if err != nil {
							zap.L().Sugar().Warnf("poolcontroller %s:%d tree request error: %v", target.Hostname, target.Port, err)
							responseChan <- treeResponse{nil, target, err}
							return
						}
						
						var respMap map[string]interface{}
						if err := json.Unmarshal(resBytes, &respMap); err != nil {
							zap.L().Sugar().Warnf("poolcontroller %s:%d tree invalid response: %v", target.Hostname, target.Port, err)
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
										}
									}
								}
							}
						}
					}
				}

				// If we couldn't build a base response, fall back to default handling
				if baseResp == nil {
					// fall through to other handlers
				} else {
					// Merge: non-cluster from base + all clusters from all controllers
					if cdt, ok := baseResp["cdt"].(map[string]interface{}); ok {
						merged := make([]interface{}, 0, len(baseNonCluster)+len(clusterItems))
						merged = append(merged, baseNonCluster...)
						merged = append(merged, clusterItems...)
						cdt["sub_items"] = merged
					}
					b, _ := json.Marshal(baseResp)
					ctx.Data(http.StatusOK, "application/json", b)
					return true
				}
			}
		}
	}

	// Special handling: /clusters getAllClusterInfo aggregation
	if strings.Contains(ctx.Request.URL.Path, "/clusters") {
		var withOp cmonapi.WithOperation
		_ = json.Unmarshal(jsonData, &withOp)
		if strings.EqualFold(withOp.Operation, "getAllClusterInfo") {
			for _, addr := range proxy.Router(ctx).Urls() {
				c := proxy.Router(ctx).Cmon(addr)
				if c == nil || c.Client == nil || !c.MatchesID(controllerId) { continue }
				data, ok := aggregateListAcrossPoolControllers(ctx, c.Client, activeTargets, ctx.Request.URL.EscapedPath(), jsonData, []string{"clusters"}, nil, false, 0, 0)
				if ok { ctx.Data(http.StatusOK, "application/json", data); return true }
			}
		}
	}

	// Backups aggregation: /backup getBackups with pagination
	if strings.Contains(ctx.Request.URL.Path, "/backup") {
		var body map[string]interface{}
		_ = json.Unmarshal(jsonData, &body)
		op, _ := body["operation"].(string)
		var (
			limit, offset int
			ascending bool
		)
		if v, ok := body["limit"].(float64); ok { limit = int(v) }
		if v, ok := body["offset"].(float64); ok { offset = int(v) }
		if v, ok := body["ascending"].(bool); ok { ascending = v }
		if strings.EqualFold(op, "getBackups") {
			delete(body, "limit"); delete(body, "offset"); delete(body, "ascending"); delete(body, "order")
			jsonData, _ = json.Marshal(body)
			for _, addr := range proxy.Router(ctx).Urls() {
				c := proxy.Router(ctx).Cmon(addr)
				if c == nil || c.Client == nil || !c.MatchesID(controllerId) { continue }
				data, ok := aggregateListAcrossPoolControllers(ctx, c.Client, activeTargets, ctx.Request.URL.EscapedPath(), jsonData, []string{"backup_records"}, func(m map[string]interface{}) time.Time {
					if md, ok := m["metadata"].(map[string]interface{}); ok {
						if s, ok := md["created"].(string); ok { if t, err := time.Parse(time.RFC3339, s); err == nil { return t } }
					}
					return time.Time{}
				}, ascending, limit, offset)
				if ok { ctx.Data(http.StatusOK, "application/json", data); return true }
				break
			}
		}
	}

	// Generic aggregation: reports/jobs/alarms/audit/maintenance
	if strings.Contains(ctx.Request.URL.Path, "/reports") || strings.Contains(ctx.Request.URL.Path, "/jobs") || strings.Contains(ctx.Request.URL.Path, "/alarms") || strings.Contains(ctx.Request.URL.Path, "/audit") || strings.Contains(ctx.Request.URL.Path, "/maintenance") {
		var body map[string]interface{}
		_ = json.Unmarshal(jsonData, &body)
		op, _ := body["operation"].(string)
		var (
			limit, offset int
			ascending bool
		)
		if v, ok := body["limit"].(float64); ok { limit = int(v) }
		if v, ok := body["offset"].(float64); ok { offset = int(v) }
		if v, ok := body["ascending"].(bool); ok { ascending = v }
		if strings.EqualFold(op, "getReports") || strings.EqualFold(op, "listSchedules") || strings.EqualFold(op, "getAlarms") || strings.EqualFold(op, "getEntries") || strings.EqualFold(op, "getMaintenance") || strings.EqualFold(op, "getJobInstances") {
			delete(body, "limit"); delete(body, "offset"); delete(body, "ascending"); delete(body, "order")
			jsonData, _ = json.Marshal(body)
			for _, addr := range proxy.Router(ctx).Urls() {
				c := proxy.Router(ctx).Cmon(addr)
				if c == nil || c.Client == nil || !c.MatchesID(controllerId) { continue }
				data, ok := aggregateListAcrossPoolControllers(ctx, c.Client, activeTargets, ctx.Request.URL.EscapedPath(), jsonData, []string{"reports","data", "jobs", "alarms", "audit_entries", "maintenance_records"}, func(m map[string]interface{}) time.Time {
					for _, k := range []string{"created", "created_time", "created_ts"} {
						if s, ok := m[k].(string); ok { if t, err := time.Parse(time.RFC3339, s); err == nil { return t } }
					}
					return time.Time{}
				}, ascending, limit, offset)
				if ok { ctx.Data(http.StatusOK, "application/json", data); return true }
				break
			}
		}
	}

	return false
}

// aggregateListAcrossPoolControllers fans out a request to the given pool controllers in parallel,
// aggregates list fields in listKeys, sorts using tsExtractor (if provided), paginates
// and returns marshaled base response with merged lists and total.
func aggregateListAcrossPoolControllers(
	ctx *gin.Context,
	baseClient *cmon.Client,
	targets []*cmonapi.PoolController,
	path string,
	body []byte,
	listKeys []string,
	tsExtractor func(map[string]interface{}) time.Time,
	ascending bool,
	limit int,
	offset int,
) ([]byte, bool) {
	if len(targets) == 0 {
		return nil, false
	}

	// Channel to collect responses from parallel requests
	type poolResponse struct {
		response map[string]interface{}
		target   *cmonapi.PoolController
		err      error
	}

	responseChan := make(chan poolResponse, len(targets))
	var wg sync.WaitGroup

	// Launch parallel requests to all pool controllers
	for _, target := range targets {
		wg.Add(1)
		go func(target *cmonapi.PoolController) {
			defer wg.Done()
			
			instCopy := *baseClient.Instance
			instCopy.Url = target.Hostname + ":" + strconv.Itoa(target.Port+1)
			timeout := proxy.Router(ctx).Config.Timeout
			if timeout <= 0 { timeout = 10 }
			tmpClient := cmon.NewClient(&instCopy, timeout)
			if cookie := baseClient.GetSessionCookie(); cookie != nil { 
				tmpClient.SetSessionCookie(cookie) 
			}
			
			resBytes, err := tmpClient.RequestBytes(path, body, false)
			if err != nil {
				zap.L().Sugar().Warnf("poolcontroller %s:%d list request error: %v", target.Hostname, target.Port, err)
				responseChan <- poolResponse{nil, target, err}
				return
			}
			
			var respMap map[string]interface{}
			if err := json.Unmarshal(resBytes, &respMap); err != nil {
				zap.L().Sugar().Warnf("poolcontroller %s:%d list invalid response: %v", target.Hostname, target.Port, err)
				responseChan <- poolResponse{nil, target, err}
				return
			}
			
			responseChan <- poolResponse{respMap, target, nil}
		}(target)
	}

	// Wait for all goroutines to complete
	wg.Wait()
	close(responseChan)

	// Collect and aggregate responses
	var baseResp map[string]interface{}
	aggregated := make([]map[string]interface{}, 0, 256)
	
	for resp := range responseChan {
		if resp.err != nil || resp.response == nil {
			continue
		}
		
		if baseResp == nil {
			baseResp = resp.response
		}
		
		for _, key := range listKeys {
			if lst, ok := resp.response[key].([]interface{}); ok {
				for _, it := range lst {
					if m, ok := it.(map[string]interface{}); ok {
						aggregated = append(aggregated, m)
					}
				}
			}
		}
	}

	if baseResp == nil {
		return nil, false
	}

	if tsExtractor != nil {
		sort.SliceStable(aggregated, func(i, j int) bool {
			ti := tsExtractor(aggregated[i])
			tj := tsExtractor(aggregated[j])
			if ascending { return ti.Before(tj) }
			return ti.After(tj)
		})
	}

	total := len(aggregated)
	start := offset
	if start < 0 { start = 0 }
	if start > total { start = total }
	end := total
	if limit > 0 && start+limit < end { end = start + limit }

	sliced := aggregated[start:end]
	out := make([]interface{}, len(sliced))
	for i, m := range sliced { out[i] = m }

	for _, key := range listKeys {
		baseResp[key] = out
	}
	baseResp["total"] = int64(total)

	b, _ := json.Marshal(baseResp)
	return b, true
}

// trySmartRouteAcrossPoolForSingle is an adapted version of trySmartRouteAcrossPool for single controller mode
// It performs the same smart routing logic but uses the provided single controller instance instead of proxy.Router()
func trySmartRouteAcrossPoolForSingle(
	ctx *gin.Context,
	jsonData []byte,
	activeTargets []*cmonapi.PoolController,
	controllerInstance *config.CmonInstance,
) bool {
	if len(activeTargets) < 1 { return false }

	var bodyMap map[string]interface{}
	_ = json.Unmarshal(jsonData, &bodyMap)
	var (
		op string
		clusterId = -1
		clusterIdStr string
	)
	if bodyMap != nil {
		op, _ = bodyMap["operation"].(string)
		if v, ok := bodyMap["cluster_id"]; ok {
			switch t := v.(type) {
			case float64:
				clusterId = int(t)
				clusterIdStr = strconv.FormatInt(int64(t), 10)
			case string:
				clusterIdStr = t
				if n, err := strconv.Atoi(t); err == nil { clusterId = n }
			}
		}
	}

	// Helper to forward request to a specific pool-controller (adapted for single mode)
	forwardTo := func(chosen *cmonapi.PoolController, warnPrefix string) bool {
		if chosen == nil { return false }
		
		// Create temporary client for the pool controller (using single controller config as base)
		instCopy := *controllerInstance
		instCopy.Url = chosen.Hostname + ":" + strconv.Itoa(chosen.Port+1)
		
		timeout := 30 // Default timeout for single controller mode
		tmpClient := cmon.NewClient(&instCopy, timeout)
		
		// Try to get session cookie from the main controller if available
		// Note: This would need access to the main controller's client for auth
		resBytes, err := tmpClient.RequestBytes(ctx.Request.URL.EscapedPath(), jsonData, false)
		if err != nil {
			zap.L().Sugar().Warnf("%s %s:%d request error: %v", warnPrefix, chosen.Hostname, chosen.Port, err)
			return false
		}
		ctx.Data(http.StatusOK, "application/json", resBytes)
		return true
	}

	// If multiple active pool-controllers, perform smart routing (same logic as multi-controller)
	if len(activeTargets) > 1 {
		// Special case: createJobInstance with cluster_id=0 → choose least-loaded pool-controller
		if strings.EqualFold(op, "createJobInstance") && clusterId == 0 {
			var chosen *cmonapi.PoolController
			minClusters := 0
			for i, pc := range activeTargets {
				l := len(pc.Clusters)
				if i == 0 || l < minClusters { minClusters = l; chosen = pc }
			}
			if forwardTo(chosen, "poolcontroller createJobInstance cluster_id=0") { return true }
		}

		// If request targets a specific cluster, route directly to the controller handling it
		if clusterIdStr != "" {
			var chosen *cmonapi.PoolController
			for _, pc := range activeTargets {
				for _, cid := range pc.Clusters {
					if cid == clusterIdStr { chosen = pc; break }
				}
				if chosen != nil { break }
			}
			if forwardTo(chosen, "poolcontroller cluster-directed") { return true }
		}
	}

	// Aggregation endpoints - these need special handling for single controller mode
	// For now, we'll implement basic aggregation, more sophisticated aggregation can be added later
	
	// Tree aggregation endpoint
	if strings.Contains(ctx.Request.URL.Path, "/tree") {
		var withOp cmonapi.WithOperation
		_ = json.Unmarshal(jsonData, &withOp)
		if strings.EqualFold(withOp.Operation, "getTree") {
			return aggregateTreeAcrossPoolForSingle(ctx, jsonData, activeTargets, controllerInstance)
		}
	}

	// Other aggregation endpoints could be added here
	// - Clusters aggregation
	// - Jobs aggregation  
	// - Alarms aggregation
	// - Backup aggregation
	// - etc.

	return false
}

// aggregateTreeAcrossPoolForSingle performs tree aggregation for single controller mode
func aggregateTreeAcrossPoolForSingle(
	ctx *gin.Context,
	jsonData []byte,
	activeTargets []*cmonapi.PoolController,
	controllerInstance *config.CmonInstance,
) bool {
	// Prepare aggregation containers
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
	
	responses := make(chan treeResponse, len(activeTargets))
	var wg sync.WaitGroup
	
	// Make parallel requests to all active pool controllers
	for _, target := range activeTargets {
		wg.Add(1)
		go func(pc *cmonapi.PoolController) {
			defer wg.Done()
			
			// Create client for this pool controller
			instCopy := *controllerInstance
			instCopy.Url = pc.Hostname + ":" + strconv.Itoa(pc.Port+1)
			
			timeout := 30
			tmpClient := cmon.NewClient(&instCopy, timeout)
			
			resBytes, err := tmpClient.RequestBytes(ctx.Request.URL.EscapedPath(), jsonData, false)
			
			resp := treeResponse{target: pc, err: err}
			if err == nil {
				_ = json.Unmarshal(resBytes, &resp.response)
			}
			responses <- resp
		}(target)
	}
	
	// Wait for all requests to complete
	go func() {
		wg.Wait()
		close(responses)
	}()
	
	// Process responses
	for resp := range responses {
		if resp.err != nil {
			zap.L().Sugar().Warnf("Tree aggregation error from %s:%d: %v", resp.target.Hostname, resp.target.Port, resp.err)
			continue
		}
		
		if resp.response == nil {
			continue
		}
		
		// Use first successful response as base structure
		if baseResp == nil {
			baseResp = resp.response
			// Extract non-cluster items from base response
			if tree, ok := baseResp["tree"].([]interface{}); ok {
				for _, item := range tree {
					if itemMap, ok := item.(map[string]interface{}); ok {
						if itemType, ok := itemMap["type"].(string); ok && itemType != "cluster" {
							baseNonCluster = append(baseNonCluster, item)
						}
					}
				}
			}
		}
		
		// Extract cluster items and deduplicate
		if tree, ok := resp.response["tree"].([]interface{}); ok {
			for _, item := range tree {
				if itemMap, ok := item.(map[string]interface{}); ok {
					if itemType, ok := itemMap["type"].(string); ok && itemType == "cluster" {
						if clusterIdVal, ok := itemMap["cluster_id"]; ok {
							clusterKey := fmt.Sprintf("%v", clusterIdVal)
							if !seenClusters[clusterKey] {
								seenClusters[clusterKey] = true
								clusterItems = append(clusterItems, item)
							}
						}
					}
				}
			}
		}
	}
	
	// If no successful responses, return false to fall back
	if baseResp == nil {
		return false
	}
	
	// Combine non-cluster items with deduplicated cluster items
	combinedTree := append(baseNonCluster, clusterItems...)
	baseResp["tree"] = combinedTree
	
	// Send aggregated response
	ctx.JSON(http.StatusOK, baseResp)
	return true
}