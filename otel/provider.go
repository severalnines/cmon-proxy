package otel

import (
	"encoding/json"
	"time"

	"github.com/severalnines/cmon-proxy/cmon/api"
	"github.com/severalnines/cmon-proxy/multi/router"
	"go.uber.org/zap"
)

// ClusterDataProvider abstracts the source of cluster/host data.
type ClusterDataProvider interface {
	FetchAllClusters() map[string]*ControllerClusters
}

// ControllerClusters holds the cluster data for a single controller.
type ControllerClusters struct {
	ControllerID string
	Clusters     []*api.Cluster
	Err          error
	HostStats    map[uint64]*HostHardwareStats
}

// HostHardwareStats holds hardware specs for a single host.
type HostHardwareStats struct {
	VCPU     *int
	RAMMB    *int
	VolumeGB *int
}

// RouterAdapter wraps a Router to implement ClusterDataProvider.
type RouterAdapter struct {
	router *router.Router
}

// NewRouterAdapter creates a ClusterDataProvider backed by a Router.
func NewRouterAdapter(r *router.Router) *RouterAdapter {
	return &RouterAdapter{router: r}
}

// FetchAllClusters returns per-controller cluster data. It prefers the
// lightweight getMeteringData endpoint when available and falls back to
// getAllClusterInfo plus statByName for older controllers.
func (a *RouterAdapter) FetchAllClusters() map[string]*ControllerClusters {
	log := zap.L().Sugar()

	urls := a.router.Urls()
	log.Debugf("[otel-provider] Router has %d URLs: %v", len(urls), urls)

	result := make(map[string]*ControllerClusters)
	fetchedFallbackClusters := false

	for _, addr := range urls {
		if addr == "" {
			continue
		}
		cmonEntry := a.router.Cmon(addr)
		if cmonEntry == nil {
			continue
		}

		xid := cmonEntry.Xid()
		if xid == "" {
			// cc.controller.id is the stable cross-boundary identifier that
			// cc-telemetry uses to key node_snapshots. Emitting an internal
			// router URL as the id would (a) leak that URL into the billing
			// DB and (b) re-key every node the instant the xid settles on a
			// later ping, creating a ghost controller's worth of snapshots.
			// Defer until xid is known.
			log.Warnf("[otel-provider] controller %s has no xid yet; skipping this emit", addr)
			continue
		}
		cc := &ControllerClusters{ControllerID: xid}

		client := a.router.Client(addr)
		if client != nil {
			clusters, hostStats, err := fetchMeteringData(client)
			if err == nil {
				cc.Clusters = clusters
				cc.HostStats = hostStats
				log.Debugf("[otel-provider] Controller %s returned %d metering clusters", addr, len(cc.Clusters))
			} else {
				log.Debugf("[otel-provider] getMeteringData unavailable for controller %s, falling back to cached cluster info: %v", addr, err)
			}
		}

		if cc.Clusters == nil {
			if !fetchedFallbackClusters {
				a.router.GetAllClusterInfo(true)
				fetchedFallbackClusters = true
			}
			if cmonEntry.Clusters != nil && cmonEntry.Clusters.Clusters != nil {
				cc.Clusters = cmonEntry.Clusters.Clusters
				log.Debugf("[otel-provider] Controller %s returned %d fallback clusters", addr, len(cc.Clusters))
			} else {
				log.Debugf("[otel-provider] Controller %s has no cluster data cached", addr)
			}
			if client != nil && cc.Clusters != nil {
				cc.HostStats = fetchHostStats(client, cc.Clusters)
			}
		}

		result[addr] = cc
	}

	return result
}

func fetchMeteringData(client interface {
	GetMeteringData(*api.GetMeteringDataRequest) (*api.GetMeteringDataResponse, error)
	GetCpuPhysicalInfo(*api.GetCpuPhysicalInfoRequest) (*api.GetCpuPhysicalInfoResponse, error)
}) ([]*api.Cluster, map[uint64]*HostHardwareStats, error) {
	resp, err := client.GetMeteringData(&api.GetMeteringDataRequest{
		WithOperation: &api.WithOperation{Operation: "getMeteringData"},
	})
	if err != nil {
		return nil, nil, err
	}

	clusters := make([]*api.Cluster, 0, len(resp.Clusters))
	hostStats := make(map[uint64]*HostHardwareStats)
	for _, cluster := range resp.Clusters {
		if cluster == nil {
			continue
		}
		converted := &api.Cluster{
			ClusterID:   cluster.ClusterID,
			ClusterName: cluster.ClusterName,
			ClusterType: cluster.ClusterType,
			Vendor:      cluster.Vendor,
			Tags:        cluster.Tags,
		}

		for _, host := range cluster.Hosts {
			if host == nil {
				continue
			}
			converted.Hosts = append(converted.Hosts, &api.Host{
				WithClassName: &api.WithClassName{ClassName: host.ClassName},
				HostID:        host.HostID,
				Hostname:      host.Hostname,
				IP:            host.IP,
				Port:          api.CmonInt(host.Port),
				HostStatus:    host.HostStatus,
				Nodetype:      host.NodeType,
				Role:          host.Role,
				ElasticRoles:  host.ElasticRoles,
			})

			stats := &HostHardwareStats{}
			if host.NCPUs != nil {
				vcpu := *host.NCPUs
				stats.VCPU = &vcpu
			}
			if host.TotalMemoryMB != nil {
				ramMB := *host.TotalMemoryMB
				stats.RAMMB = &ramMB
			}
			if host.LargestDiskMB != nil {
				volumeGB := *host.LargestDiskMB / 1024
				stats.VolumeGB = &volumeGB
			}
			hostStats[host.HostID] = stats
		}

		fillMissingVCPUFromCPUInfo(client, cluster.ClusterID, hostStats)

		clusters = append(clusters, converted)
	}

	return clusters, hostStats, nil
}

func fillMissingVCPUFromCPUInfo(client interface {
	GetCpuPhysicalInfo(*api.GetCpuPhysicalInfoRequest) (*api.GetCpuPhysicalInfoResponse, error)
}, clusterID uint64, hostStats map[uint64]*HostHardwareStats) {
	if !hasHostMissingVCPU(hostStats) {
		return
	}

	resp, err := client.GetCpuPhysicalInfo(&api.GetCpuPhysicalInfoRequest{
		WithOperation: &api.WithOperation{Operation: "getCpuPhysicalInfo"},
		WithClusterID: &api.WithClusterID{ClusterID: clusterID},
	})
	if err != nil || resp == nil {
		return
	}

	perHostVCPU := make(map[uint64]int)
	seenPhysicalCPU := make(map[uint64]map[int]bool)
	for _, cpuInfo := range resp.Data {
		if cpuInfo == nil {
			continue
		}

		threads := cpuInfo.Siblings
		if threads <= 0 {
			threads = cpuInfo.CpuCores
		}
		if threads <= 0 {
			continue
		}

		if seenPhysicalCPU[cpuInfo.HostID] == nil {
			seenPhysicalCPU[cpuInfo.HostID] = make(map[int]bool)
		}
		if seenPhysicalCPU[cpuInfo.HostID][cpuInfo.PhysicalCPUID] {
			continue
		}
		seenPhysicalCPU[cpuInfo.HostID][cpuInfo.PhysicalCPUID] = true
		perHostVCPU[cpuInfo.HostID] += threads
	}

	for hostID, vcpu := range perHostVCPU {
		if hostStats[hostID] == nil {
			hostStats[hostID] = &HostHardwareStats{}
		}
		if hostStats[hostID].VCPU == nil {
			value := vcpu
			hostStats[hostID].VCPU = &value
		}
	}
}

func hasHostMissingVCPU(hostStats map[uint64]*HostHardwareStats) bool {
	if len(hostStats) == 0 {
		return true
	}
	for _, stats := range hostStats {
		if stats == nil || stats.VCPU == nil {
			return true
		}
	}
	return false
}

func fetchHostStats(client interface {
	GetStatByName(*api.GetStatByNameRequest) (*api.GetStatByNameResponse, error)
}, clusters []*api.Cluster) map[uint64]*HostHardwareStats {
	log := zap.L().Sugar()
	stats := make(map[uint64]*HostHardwareStats)

	now := time.Now().UTC()
	startTime := now.Add(-10 * time.Minute)

	clusterIDs := make(map[uint64]bool)
	for _, c := range clusters {
		clusterIDs[c.ClusterID] = true
	}

	for cid := range clusterIDs {
		memResp, err := client.GetStatByName(&api.GetStatByNameRequest{
			WithOperation: &api.WithOperation{Operation: "statByName"},
			WithClusterID: &api.WithClusterID{ClusterID: cid},
			Name:          api.StatTypeMemoryStat,
			WithHosts:     true,
			StartDateTime: api.StatTS(startTime),
			EndDateTime:   api.StatTS(now),
		})
		if err != nil {
			log.Debugf("[otel] memorystat error for cluster %d: %v", cid, err)
		} else {
			parseMemoryStats(memResp.Data, stats)
		}

		diskResp, err := client.GetStatByName(&api.GetStatByNameRequest{
			WithOperation: &api.WithOperation{Operation: "statByName"},
			WithClusterID: &api.WithClusterID{ClusterID: cid},
			Name:          api.StatTypeDiskStat,
			WithHosts:     true,
			StartDateTime: api.StatTS(startTime),
			EndDateTime:   api.StatTS(now),
		})
		if err != nil {
			log.Debugf("[otel] diskstat error for cluster %d: %v", cid, err)
		} else {
			parseDiskStats(diskResp.Data, stats)
		}
	}

	return stats
}

type memoryStat struct {
	HostID   uint64 `json:"hostid"`
	RAMTotal int64  `json:"ramtotal"`
}

func parseMemoryStats(data json.RawMessage, stats map[uint64]*HostHardwareStats) {
	var entries []memoryStat
	if err := json.Unmarshal(data, &entries); err != nil {
		zap.L().Sugar().Debugf("[otel-provider] parse memorystat: %v", err)
		return
	}
	for _, e := range entries {
		if e.RAMTotal <= 0 {
			continue
		}
		// memorystat.ramtotal is reported in KB; convert to MB for the
		// billing wire shape.
		ramMB := int(e.RAMTotal / 1024)
		if hw, ok := stats[e.HostID]; ok {
			hw.RAMMB = &ramMB
		} else {
			stats[e.HostID] = &HostHardwareStats{RAMMB: &ramMB}
		}
	}
}

type diskStat struct {
	HostID uint64 `json:"hostid"`
	Total  int64  `json:"total"`
}

func parseDiskStats(data json.RawMessage, stats map[uint64]*HostHardwareStats) {
	var entries []diskStat
	if err := json.Unmarshal(data, &entries); err != nil {
		zap.L().Sugar().Debugf("[otel-provider] parse diskstat: %v", err)
		return
	}
	maxDisk := make(map[uint64]int64)
	for _, e := range entries {
		if e.Total > maxDisk[e.HostID] {
			maxDisk[e.HostID] = e.Total
		}
	}
	for hostID, total := range maxDisk {
		volGB := int(total / (1024 * 1024 * 1024))
		if hw, ok := stats[hostID]; ok {
			hw.VolumeGB = &volGB
		} else {
			stats[hostID] = &HostHardwareStats{VolumeGB: &volGB}
		}
	}
}

// Eligible node classification — same logic as metering/models.go.

// Exclusions worth calling out:
//   - CmonRedisSentinelHost: sentinels don't serve data, only observe the
//     Redis replication topology. Not billable.
//   - CmonPrometheusHost: monitoring sidecar, not a DB.
//   - Controller hosts (filtered upstream by host.Nodetype == "controller").
//
// Redis-sharded currently comes over the wire as "RedisShardedHost" (no
// "Cmon" prefix); keep both spellings in case CMON retrofits the prefix.
// Must stay in sync with cc-telemetry's internal/metering/models.go.
var eligibleDBClassNames = map[string]bool{
	"CmonMySqlHost": true, "CmonGaleraHost": true, "CmonElasticHost": true,
	"CmonRedisHost": true, "RedisShardedHost": true, "CmonRedisShardedHost": true,
	"CmonGroupReplHost": true, "CmonMongoHost": true, "CmonNdbHost": true,
	"CmonPostgreSqlHost": true, "CmonMsSqlHost": true,
}

var eligibleProxyClassNames = map[string]bool{
	"CmonProxySqlHost": true,
}

// IsEligibleNode returns true if the given class name represents a billable node.
func IsEligibleNode(className string) bool {
	return eligibleDBClassNames[className] || eligibleProxyClassNames[className]
}

// nonDataMongoRoles marks MongoDB roles whose hosts don't serve data and
// therefore shouldn't be billed. For Mongo Shards this excludes config
// servers ("configsvr"), routers ("mongos"), and arbiters ("arbiter").
// Shard data nodes ("shardsvr") and plain replicaset members (which
// inherit "shardsvr" too, see cc-cmon/src/cmonmongohost.cpp:106-123) stay
// eligible. Role strings are CMON's canonical outputs from
// CmonMongoHost::setRoleId.
var nonDataMongoRoles = map[string]bool{
	"configsvr": true,
	"mongos":    true,
	"arbiter":   true,
}

// elasticHasDataRole returns true if the hyphen-delimited elastic_roles
// string CMON emits for an Elasticsearch host contains any data-bearing
// role. When the field is empty (e.g. cluster not yet populated, or
// cc-cmon not emitting it via getMeteringData) we default to eligible
// so we don't silently regress existing Elastic deployments — the filter
// only narrows when roles are known.
func elasticHasDataRole(roles string) bool {
	if roles == "" {
		return true
	}
	// Walk the hyphen-delimited segments. Data roles: "data", "data_content",
	// "data_hot", "data_warm", "data_cold", "data_frozen".
	// See cc-cmon/src/cmonelastichost.cpp:298-353 getRolesStr for the
	// canonical string forms.
	start := 0
	for i := 0; i <= len(roles); i++ {
		if i == len(roles) || roles[i] == '-' {
			seg := roles[start:i]
			if seg == "data" ||
				seg == "data_content" ||
				seg == "data_hot" ||
				seg == "data_warm" ||
				seg == "data_cold" ||
				seg == "data_frozen" {
				return true
			}
			start = i + 1
		}
	}
	return false
}

// IsEligibleHost returns true if the given host should be billed. It
// subsumes IsEligibleNode(className) and layers role-aware guards for
// cluster types where a single class covers both billable and
// non-billable roles (MongoDB Shards: shardsvr vs configsvr/mongos;
// Elasticsearch: data-bearing vs master/ingest/coordinator-only).
func IsEligibleHost(h *api.Host) bool {
	if h == nil || h.Nodetype == "controller" {
		return false
	}
	className := ""
	if h.WithClassName != nil {
		className = h.ClassName
	}
	if !IsEligibleNode(className) {
		return false
	}
	switch className {
	case "CmonMongoHost":
		return !nonDataMongoRoles[h.Role]
	case "CmonElasticHost":
		return elasticHasDataRole(h.ElasticRoles)
	}
	return true
}

// NodeRoleFromClassName returns the metering node role for a CMON host class name.
func NodeRoleFromClassName(className string) string {
	if eligibleProxyClassNames[className] {
		return "proxysql"
	}
	return "database"
}

// NormalizeVendor maps CMON vendor strings to normalized names.
func NormalizeVendor(vendor string) string {
	switch vendor {
	case "percona", "Percona":
		return "percona"
	case "oracle", "Oracle":
		return "oracle"
	case "mariadb", "MariaDB":
		return "mariadb"
	case "10gen", "MongoDB", "mongodb":
		return "mongodb"
	case "redis", "Redis", "Redis Labs":
		return "redis"
	case "microsoft", "Microsoft":
		return "microsoft"
	case "elastic", "Elastic":
		return "elastic"
	case "postgresql", "PostgreSQL":
		return "postgresql"
	case "valkey", "Valkey":
		return "valkey"
	case "timescaledb", "TimescaleDB":
		return "timescaledb"
	default:
		if vendor == "" {
			return "community"
		}
		return vendor
	}
}
