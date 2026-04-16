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
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/severalnines/cmon-proxy/cmon/api"
	"go.uber.org/zap"
)

// ClusterDataProvider abstracts the source of cluster/host data.
// In production this is backed by the Router; in tests it can be stubbed.
type ClusterDataProvider interface {
	// FetchAllClusters forces a refresh and returns per-controller cluster data.
	FetchAllClusters() map[string]*ControllerClusters
}

// ControllerClusters holds the cluster data for a single controller.
type ControllerClusters struct {
	ControllerID string
	Clusters     []*api.Cluster
	Err          error
}

// Collector periodically captures node state snapshots from all controllers.
type Collector struct {
	storage  StorageBackend
	provider ClusterDataProvider
	interval time.Duration
	logger   *zap.SugaredLogger

	// previousNodes tracks which nodes were seen in the last collection,
	// keyed by node_id. Used to detect removed nodes.
	previousNodes map[string]bool
	mu            sync.Mutex

	stopCh chan struct{}
	done   chan struct{}
}

// NewCollector creates a new metering collector.
func NewCollector(storage StorageBackend, provider ClusterDataProvider, interval time.Duration) *Collector {
	return &Collector{
		storage:       storage,
		provider:      provider,
		interval:      interval,
		logger:        zap.L().Sugar(),
		previousNodes: make(map[string]bool),
		stopCh:        make(chan struct{}),
		done:          make(chan struct{}),
	}
}

// Start begins the collection loop. It runs a catch-up collection if needed,
// then starts the periodic ticker aligned to the next interval boundary.
func (c *Collector) Start() {
	go c.run()
}

// Stop signals the collector to stop and waits for it to finish.
func (c *Collector) Stop() {
	close(c.stopCh)
	<-c.done
}

func (c *Collector) run() {
	defer close(c.done)

	ctx := context.Background()

	// Check if we need a catch-up collection.
	lastCollection, err := c.storage.GetConfig(ctx, ConfigLastSuccessfulCollection)
	if err != nil {
		c.logger.Warnf("[metering] failed to read last collection time: %v", err)
	}

	needsCatchUp := true
	if lastCollection != "" {
		if t, err := parseTimestamp(lastCollection); err == nil {
			if time.Since(t) < c.interval {
				needsCatchUp = false
			}
		}
	}

	if needsCatchUp {
		c.logger.Info("[metering] running catch-up collection on startup")
		c.collect(ctx)
	}

	// Align to the next interval boundary.
	now := time.Now()
	next := now.Truncate(c.interval).Add(c.interval)
	alignDelay := next.Sub(now)

	c.logger.Infof("[metering] next collection at %s (in %s)", next.Format(time.RFC3339), alignDelay)

	alignTimer := time.NewTimer(alignDelay)
	defer alignTimer.Stop()

	select {
	case <-c.stopCh:
		return
	case <-alignTimer.C:
	}

	// Run the first aligned collection.
	c.collect(ctx)

	// Start the periodic ticker.
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.collect(ctx)
		}
	}
}

// collect performs a single snapshot collection cycle.
func (c *Collector) collect(ctx context.Context) {
	now := time.Now().UTC().Truncate(time.Second)
	c.logger.Infof("[metering] starting collection at %s", now.Format(time.RFC3339))

	controllerData := c.provider.FetchAllClusters()
	if len(controllerData) == 0 {
		c.logger.Warn("[metering] no controllers returned data")
		return
	}

	var snapshots []NodeSnapshot
	currentNodes := make(map[string]bool)

	for addr, data := range controllerData {
		if data.Err != nil {
			c.logger.Warnf("[metering] controller %s returned error: %v (skipping, not marking nodes removed)", addr, data.Err)
			// Preserve previous node set for this controller — don't mark as removed.
			c.mu.Lock()
			for nodeID := range c.previousNodes {
				// Keep nodes from errored controllers in the "previous" set.
				// A simple prefix check identifies which nodes belong to this controller.
				if len(nodeID) > len(data.ControllerID) && nodeID[:len(data.ControllerID)+1] == data.ControllerID+":" {
					currentNodes[nodeID] = true
				}
			}
			c.mu.Unlock()
			continue
		}

		for _, cluster := range data.Clusters {
			for _, host := range cluster.Hosts {
				if host == nil || host.Nodetype == "controller" {
					continue
				}

				className := ""
				if host.WithClassName != nil {
					className = host.ClassName
				}

				if !IsEligibleNode(className) {
					continue
				}

				nodeID := fmt.Sprintf("%s:%s", data.ControllerID, host.IP)
				currentNodes[nodeID] = true

				status := nodeStatusFromHostStatus(host.HostStatus)

				snap := NodeSnapshot{
					CapturedAt:   now,
					ControllerID: data.ControllerID,
					ClusterID:    cluster.ClusterID,
					ClusterName:  cluster.ClusterName,
					ClusterType:  cluster.ClusterType,
					DBVendor:     NormalizeVendor(cluster.Vendor),
					NodeID:       nodeID,
					Hostname:     host.Hostname,
					Port:         int(host.Port),
					NodeRole:     NodeRoleFromClassName(className),
					NodeStatus:   status,
					Tags:         cluster.Tags,
				}

				snapshots = append(snapshots, snap)
			}
		}
	}

	// Detect removed nodes: in previous set but not in current set.
	c.mu.Lock()
	for prevNodeID := range c.previousNodes {
		if !currentNodes[prevNodeID] {
			snapshots = append(snapshots, NodeSnapshot{
				CapturedAt: now,
				NodeID:     prevNodeID,
				NodeStatus: NodeStatusRemoved,
				// Minimal fields — the node is gone, so we only record its removal.
				// The full metadata is available in prior snapshot rows.
				ControllerID: extractControllerID(prevNodeID),
				NodeRole:     NodeRoleDatabase, // default; actual role is in prior snapshots
			})
		}
	}
	c.previousNodes = currentNodes
	c.mu.Unlock()

	if len(snapshots) == 0 {
		c.logger.Info("[metering] no eligible nodes found")
		return
	}

	if err := c.storage.InsertSnapshots(ctx, snapshots); err != nil {
		c.logger.Errorf("[metering] failed to insert %d snapshots: %v", len(snapshots), err)
		return
	}

	// Record success.
	if err := c.storage.SetConfig(ctx, ConfigLastSuccessfulCollection, now.Format(time.RFC3339)); err != nil {
		c.logger.Warnf("[metering] failed to update last collection time: %v", err)
	}

	c.logger.Infof("[metering] collected %d snapshots", len(snapshots))
}

// nodeStatusFromHostStatus maps CMON host status strings to metering node statuses.
func nodeStatusFromHostStatus(hostStatus string) string {
	switch hostStatus {
	case "CmonHostOffline", "CmonHostShutDown":
		return NodeStatusStopped
	default:
		// CmonHostOnline, CmonHostRecovery, etc. are all considered active.
		return NodeStatusActive
	}
}

// extractControllerID extracts the controller ID prefix from a node_id string.
// node_id format: "{controller_id}:{ip}"
func extractControllerID(nodeID string) string {
	for i := len(nodeID) - 1; i >= 0; i-- {
		if nodeID[i] == ':' {
			return nodeID[:i]
		}
	}
	return nodeID
}
