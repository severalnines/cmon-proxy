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

// FetchAllClusters forces a cache refresh and returns per-controller cluster data
// including hardware stats (RAM, disk) fetched from the stat API.
func (a *RouterAdapter) FetchAllClusters() map[string]*ControllerClusters {
	a.router.GetAllClusterInfo(true)

	result := make(map[string]*ControllerClusters)

	for _, addr := range a.router.Urls() {
		cmonEntry := a.router.Cmon(addr)
		if cmonEntry == nil {
			continue
		}

		cc := &ControllerClusters{ControllerID: addr}

		if xid := cmonEntry.Xid(); xid != "" {
			cc.ControllerID = xid
		}

		if cmonEntry.Clusters != nil {
			cc.Clusters = cmonEntry.Clusters.Clusters
		}

		client := a.router.Client(addr)
		if client != nil && cc.Clusters != nil {
			cc.HostStats = fetchHostStats(client, cc.Clusters)
		}

		result[addr] = cc
	}

	return result
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
		return
	}
	for _, e := range entries {
		if e.RAMTotal <= 0 {
			continue
		}
		ramMB := int(e.RAMTotal / (1024 * 1024))
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

var eligibleDBClassNames = map[string]bool{
	"CmonMySqlHost": true, "CmonGaleraHost": true, "CmonElasticHost": true,
	"CmonRedisHost": true, "CmonRedisSentinelHost": true, "CmonGroupReplHost": true,
	"CmonMongoHost": true, "CmonNdbHost": true, "CmonPostgreSqlHost": true,
	"CmonMsSqlHost": true,
}

var eligibleProxyClassNames = map[string]bool{
	"CmonProxySqlHost": true,
}

// IsEligibleNode returns true if the given class name represents a billable node.
func IsEligibleNode(className string) bool {
	return eligibleDBClassNames[className] || eligibleProxyClassNames[className]
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
