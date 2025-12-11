package poolhelpers

// Package poolhelpers provides utility functions for routing and aggregating requests
// across pool controllers, including smart routing, fan-out aggregation, and pagination.

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
	"github.com/severalnines/cmon-proxy/multi/router"
	"go.uber.org/zap"
)

// FilterActivePoolControllers returns only active targets with valid hostname and port.
func FilterActivePoolControllers(controllers []*cmonapi.PoolController) []*cmonapi.PoolController {
	return filterActivePoolControllers(controllers)
}

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

// TrySmartRouteAcrossPool is the exported wrapper for trySmartRouteAcrossPool
// If r is nil and routerGetter is provided, uses routerGetter(ctx). If pathTransformer is nil, uses ctx.Request.URL.EscapedPath().
func TrySmartRouteAcrossPool(
	ctx *gin.Context,
	controllerId string,
	jsonData []byte,
	activeTargets []*cmonapi.PoolController,
	r *router.Router,
	pathTransformer func() string,
	routerGetter ...func(*gin.Context) *router.Router,
) bool {
	var getter func(*gin.Context) *router.Router
	if len(routerGetter) > 0 {
		getter = routerGetter[0]
	}
	return trySmartRouteAcrossPool(ctx, controllerId, jsonData, activeTargets, r, pathTransformer, getter)
}

// trySmartRouteAcrossPool attempts to route or aggregate when there are >=1 active pool controllers.
// Returns true if it produced a response and wrote to the context.
// If r is nil and routerGetter is provided, uses routerGetter(ctx). If pathTransformer is nil, uses ctx.Request.URL.EscapedPath().
func trySmartRouteAcrossPool(
	ctx *gin.Context,
	controllerId string,
	jsonData []byte,
	activeTargets []*cmonapi.PoolController,
	r *router.Router,
	pathTransformer func() string,
	routerGetter func(*gin.Context) *router.Router,
) bool {
	if len(activeTargets) < 1 {
		return false
	}

	// Get router - use provided router or fall back to routerGetter if provided
	getRouter := func() *router.Router {
		if r != nil {
			return r
		}
		if routerGetter != nil {
			return routerGetter(ctx)
		}
		return nil
	}

	// Get request path - use transformer if provided, otherwise use direct path
	getRequestPath := func() string {
		if pathTransformer != nil {
			return pathTransformer()
		}
		return ctx.Request.URL.EscapedPath()
	}

	// Mirror upstream response headers/status while stripping Set-Cookie to avoid leaking CMON cookies.
	writeRawResponse := func(raw *cmon.RawResponse) {
		if raw == nil {
			ctx.Status(http.StatusBadGateway)
			return
		}
		for key, values := range raw.Header {
			if strings.EqualFold(key, "Set-Cookie") {
				continue
			}
			for _, value := range values {
				ctx.Writer.Header().Add(key, value)
			}
		}
		ctx.Status(raw.StatusCode)
		if len(raw.Body) > 0 {
			_, _ = ctx.Writer.Write(raw.Body)
		}
	}

	var bodyMap map[string]interface{}
	_ = json.Unmarshal(jsonData, &bodyMap)
	var (
		op           string
		clusterId    = -1
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
				if n, err := strconv.Atoi(t); err == nil {
					clusterId = n
				}
			}
		}
	}

	// Helper to forward request to a specific pool-controller
	forwardTo := func(chosen *cmonapi.PoolController, warnPrefix string) bool {
		if chosen == nil {
			return false
		}
		router := getRouter()
		for _, addr := range router.Urls() {
			c := router.Cmon(addr)
			if c == nil || c.Client == nil || !c.MatchesID(controllerId) {
				continue
			}
			instCopy := *c.Client.Instance
			instCopy.Url = chosen.Hostname + ":" + strconv.Itoa(chosen.Port+1)
			timeout := router.Config.Timeout
			if timeout <= 0 {
				timeout = 10
			}
			tmpClient := cmon.NewClient(&instCopy, timeout)
			if cookie := c.Client.GetSessionCookie(); cookie != nil {
				tmpClient.SetSessionCookie(cookie)
			}
			rawResp, err := tmpClient.RequestRaw(getRequestPath(), jsonData, false)
			if err != nil {
				zap.L().Sugar().Warnf("%s %s:%d request error: %v", warnPrefix, chosen.Hostname, chosen.Port, err)
				break
			}
			// Attempt to parse JSON responses to append xid when applicable
			parsed := make(map[string]interface{})
			if err := json.Unmarshal(rawResp.Body, &parsed); err == nil && len(parsed) > 0 {
				parsed["xid"] = c.Xid()
				if payload, marshalErr := json.Marshal(parsed); marshalErr == nil {
					ctx.Data(http.StatusOK, "application/json", payload)
					return true
				}
			}
			writeRawResponse(rawResp)
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
				if i == 0 || l < minClusters {
					minClusters = l
					chosen = pc
				}
			}
			if forwardTo(chosen, "poolcontroller createJobInstance cluster_id=0") {
				return true
			}
		}

		// If request targets a specific cluster, route directly to the controller handling it
		if clusterIdStr != "" {
			var chosen *cmonapi.PoolController
			for _, pc := range activeTargets {
				for _, cid := range pc.Clusters {
					if cid == clusterIdStr {
						chosen = pc
						break
					}
				}
				if chosen != nil {
					break
				}
			}
			if forwardTo(chosen, "poolcontroller cluster-directed") {
				return true
			}
		}
	}

	// Fan-out tree aggregation: /tree with operation getTree
	if strings.Contains(ctx.Request.URL.Path, "/tree") {
		var withOp cmonapi.WithOperation
		_ = json.Unmarshal(jsonData, &withOp)
		if strings.EqualFold(withOp.Operation, "getTree") {
			router := getRouter()
			for _, addr := range router.Urls() {
				c := router.Cmon(addr)
				if c == nil || c.Client == nil || !c.MatchesID(controllerId) {
					continue
				}

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
						timeout := router.Config.Timeout
						if timeout <= 0 {
							timeout = 10
						}
						tmpClient := cmon.NewClient(&instCopy, timeout)
						if cookie := c.Client.GetSessionCookie(); cookie != nil {
							tmpClient.SetSessionCookie(cookie)
						}

						rawResp, err := tmpClient.RequestRaw(getRequestPath(), jsonData, false)
						if err != nil {
							zap.L().Sugar().Warnf("poolcontroller %s:%d tree request error: %v", target.Hostname, target.Port, err)
							responseChan <- treeResponse{nil, target, err}
							return
						}
						var respMap map[string]interface{}
						if err := json.Unmarshal(rawResp.Body, &respMap); err != nil {
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
									if m == nil {
										continue
									}
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
								if m == nil {
									continue
								}
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
			router := getRouter()
			for _, addr := range router.Urls() {
				c := router.Cmon(addr)
				if c == nil || c.Client == nil || !c.MatchesID(controllerId) {
					continue
				}
				data, ok := aggregateListAcrossPoolControllers(ctx, c.Client, activeTargets, getRequestPath(), jsonData, []string{"clusters"}, nil, false, 0, 0, router, routerGetter)
				if ok {
					ctx.Data(http.StatusOK, "application/json", data)
					return true
				}
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
			ascending     bool
		)
		if v, ok := body["limit"].(float64); ok {
			limit = int(v)
		}
		if v, ok := body["offset"].(float64); ok {
			offset = int(v)
		}
		if v, ok := body["ascending"].(bool); ok {
			ascending = v
		}
		if strings.EqualFold(op, "getBackups") {
			delete(body, "limit")
			delete(body, "offset")
			delete(body, "ascending")
			delete(body, "order")
			jsonData, _ = json.Marshal(body)
			router := getRouter()
			for _, addr := range router.Urls() {
				c := router.Cmon(addr)
				if c == nil || c.Client == nil || !c.MatchesID(controllerId) {
					continue
				}
				data, ok := aggregateListAcrossPoolControllers(ctx, c.Client, activeTargets, getRequestPath(), jsonData, []string{"backup_records"}, func(m map[string]interface{}) time.Time {
					if md, ok := m["metadata"].(map[string]interface{}); ok {
						if s, ok := md["created"].(string); ok {
							if t, err := time.Parse(time.RFC3339, s); err == nil {
								return t
							}
						}
					}
					return time.Time{}
				}, ascending, limit, offset, router, routerGetter)
				if ok {
					ctx.Data(http.StatusOK, "application/json", data)
					return true
				}
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
			ascending     bool
		)
		if v, ok := body["limit"].(float64); ok {
			limit = int(v)
		}
		if v, ok := body["offset"].(float64); ok {
			offset = int(v)
		}
		if v, ok := body["ascending"].(bool); ok {
			ascending = v
		}
		if strings.EqualFold(op, "getReports") || strings.EqualFold(op, "listSchedules") || strings.EqualFold(op, "getAlarms") || strings.EqualFold(op, "getEntries") || strings.EqualFold(op, "getMaintenance") || strings.EqualFold(op, "getJobInstances") {
			delete(body, "limit")
			delete(body, "offset")
			delete(body, "ascending")
			delete(body, "order")
			jsonData, _ = json.Marshal(body)
			router := getRouter()
			for _, addr := range router.Urls() {
				c := router.Cmon(addr)
				if c == nil || c.Client == nil || !c.MatchesID(controllerId) {
					continue
				}
				data, ok := aggregateListAcrossPoolControllers(ctx, c.Client, activeTargets, getRequestPath(), jsonData, []string{"reports", "data", "jobs", "alarms", "audit_entries", "maintenance_records"}, func(m map[string]interface{}) time.Time {
					for _, k := range []string{"created", "created_time", "created_ts"} {
						if s, ok := m[k].(string); ok {
							if t, err := time.Parse(time.RFC3339, s); err == nil {
								return t
							}
						}
					}
					return time.Time{}
				}, ascending, limit, offset, router, routerGetter)
				if ok {
					ctx.Data(http.StatusOK, "application/json", data)
					return true
				}
				break
			}
		}
	}

	return false
}

// AggregateListAcrossPoolControllers is the exported wrapper for aggregateListAcrossPoolControllers
func AggregateListAcrossPoolControllers(
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
	r *router.Router,
) ([]byte, bool) {
	return aggregateListAcrossPoolControllers(ctx, baseClient, targets, path, body, listKeys, tsExtractor, ascending, limit, offset, r, nil)
}

// aggregateListAcrossPoolControllers fans out a request to the given pool controllers in parallel,
// aggregates list fields in listKeys, sorts using tsExtractor (if provided), paginates
// and returns marshaled base response with merged lists and total.
// If r is nil and routerGetter is provided, uses routerGetter(ctx).
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
	r *router.Router,
	routerGetter func(*gin.Context) *router.Router,
) ([]byte, bool) {
	if len(targets) == 0 {
		return nil, false
	}

	// Get router - use provided router or fall back to routerGetter if provided
	getRouter := func() *router.Router {
		if r != nil {
			return r
		}
		if routerGetter != nil {
			return routerGetter(ctx)
		}
		return nil
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
			router := getRouter()
			timeout := router.Config.Timeout
			if timeout <= 0 {
				timeout = 10
			}
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

	// Track seen IDs for deduplication per key type
	seenAlarmIDs := make(map[int64]bool)
	seenJobIDs := make(map[uint64]bool)

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
						// Deduplicate alarms by alarm_id
						if key == "alarms" {
							if alarmID, ok := m["alarm_id"].(float64); ok {
								alarmIDInt := int64(alarmID)
								if seenAlarmIDs[alarmIDInt] {
									continue
								}
								seenAlarmIDs[alarmIDInt] = true
							}
						}
						// Deduplicate jobs by job_id
						if key == "jobs" {
							if jobID, ok := m["job_id"].(float64); ok {
								jobIDUint := uint64(jobID)
								if seenJobIDs[jobIDUint] {
									continue
								}
								seenJobIDs[jobIDUint] = true
							}
						}
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
			if ascending {
				return ti.Before(tj)
			}
			return ti.After(tj)
		})
	}

	total := len(aggregated)
	start := offset
	if start < 0 {
		start = 0
	}
	if start > total {
		start = total
	}
	end := total
	if limit > 0 && start+limit < end {
		end = start + limit
	}

	sliced := aggregated[start:end]
	out := make([]interface{}, len(sliced))
	for i, m := range sliced {
		out[i] = m
	}

	for _, key := range listKeys {
		baseResp[key] = out
	}
	baseResp["total"] = int64(total)

	b, _ := json.Marshal(baseResp)
	return b, true
}
