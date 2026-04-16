package metering

// Copyright 2026 Severalnines AB
//
// This file is part of cmon-proxy.
//
// cmon-proxy is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 2 of the License.
//
// cmon-proxy is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with cmon-proxy. If not, see <https://www.gnu.org/licenses/>.

import (
	"encoding/json"
	"time"

	"github.com/severalnines/cmon-proxy/cmon/api"
	"github.com/severalnines/cmon-proxy/multi/router"
	"go.uber.org/zap"
)

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
	// Force refresh from all backends.
	a.router.GetAllClusterInfo(true)

	result := make(map[string]*ControllerClusters)

	for _, addr := range a.router.Urls() {
		cmonEntry := a.router.Cmon(addr)
		if cmonEntry == nil {
			continue
		}

		cc := &ControllerClusters{
			ControllerID: addr,
		}

		// Use the controller's unique ID (xid or pool ID) if available.
		if xid := cmonEntry.Xid(); xid != "" {
			cc.ControllerID = xid
		}

		if cmonEntry.Clusters != nil {
			cc.Clusters = cmonEntry.Clusters.Clusters
		}

		// Fetch hardware stats for all clusters on this controller.
		client := a.router.Client(addr)
		if client != nil && cc.Clusters != nil {
			cc.HostStats = a.fetchHostStats(client, cc.Clusters)
		}

		result[addr] = cc
	}

	return result
}

// fetchHostStats collects memory and disk stats for all clusters and returns
// a map of hostid → hardware stats.
func (a *RouterAdapter) fetchHostStats(client interface{ GetStatByName(*api.GetStatByNameRequest) (*api.GetStatByNameResponse, error) }, clusters []*api.Cluster) map[uint64]*HostHardwareStats {
	log := zap.L().Sugar()
	stats := make(map[uint64]*HostHardwareStats)

	now := time.Now().UTC()
	// Request the last 10 minutes of stats — we only need the latest sample.
	startTime := now.Add(-10 * time.Minute)

	// Collect unique cluster IDs.
	clusterIDs := make(map[uint64]bool)
	for _, c := range clusters {
		clusterIDs[c.ClusterID] = true
	}

	for cid := range clusterIDs {
		// Fetch memory stats.
		memResp, err := client.GetStatByName(&api.GetStatByNameRequest{
			WithOperation: &api.WithOperation{Operation: "statByName"},
			WithClusterID: &api.WithClusterID{ClusterID: cid},
			Name:          api.StatTypeMemoryStat,
			WithHosts:     true,
			StartDateTime: api.StatTS(startTime),
			EndDateTime:   api.StatTS(now),
		})
		if err != nil {
			log.Debugf("[metering] failed to fetch memorystat for cluster %d: %v", cid, err)
		} else {
			parseMemoryStats(memResp.Data, stats)
		}

		// Fetch disk stats.
		diskResp, err := client.GetStatByName(&api.GetStatByNameRequest{
			WithOperation: &api.WithOperation{Operation: "statByName"},
			WithClusterID: &api.WithClusterID{ClusterID: cid},
			Name:          api.StatTypeDiskStat,
			WithHosts:     true,
			StartDateTime: api.StatTS(startTime),
			EndDateTime:   api.StatTS(now),
		})
		if err != nil {
			log.Debugf("[metering] failed to fetch diskstat for cluster %d: %v", cid, err)
		} else {
			parseDiskStats(diskResp.Data, stats)
		}
	}

	return stats
}

// memoryStat represents a single memory stat sample from the CMON stat API.
type memoryStat struct {
	HostID   uint64 `json:"hostid"`
	RAMTotal int64  `json:"ramtotal"`
}

// parseMemoryStats extracts the latest ramtotal per host from memory stat data.
func parseMemoryStats(data json.RawMessage, stats map[uint64]*HostHardwareStats) {
	var entries []memoryStat
	if err := json.Unmarshal(data, &entries); err != nil {
		return
	}

	// Take the last entry per host (entries are time-ordered).
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

// diskStat represents a single disk stat sample from the CMON stat API.
type diskStat struct {
	HostID     uint64 `json:"hostid"`
	MountPoint string `json:"mountpoint"`
	Total      int64  `json:"total"`
}

// parseDiskStats extracts the largest disk volume per host from disk stat data.
// Uses the largest mount point's total as the data volume (heuristic: the datadir
// is typically on the largest partition).
func parseDiskStats(data json.RawMessage, stats map[uint64]*HostHardwareStats) {
	var entries []diskStat
	if err := json.Unmarshal(data, &entries); err != nil {
		return
	}

	// Track max disk total per host (largest volume = likely data volume).
	maxDisk := make(map[uint64]int64)
	for _, e := range entries {
		if e.Total <= 0 {
			continue
		}
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
