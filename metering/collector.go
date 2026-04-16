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
	"strconv"
	"sync"
	"time"

	"github.com/severalnines/cmon-proxy/cmon/api"
	"go.uber.org/zap"
)

const controllerIdentityConfigPrefix = "controller_identity::"

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
	// HostStats maps hostid → hardware stats gathered from the stat API.
	HostStats map[uint64]*HostHardwareStats
}

// HostHardwareStats holds hardware specs for a single host, collected from stat APIs.
type HostHardwareStats struct {
	RAMMB    *int // total RAM in MB (from memorystat ramtotal)
	VolumeGB *int // total data volume in GB (from diskstat total, for datadir mount)
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
	hydrated      bool
	controllerIDs map[string]string

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
		controllerIDs: make(map[string]string),
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

// CollectOnce performs a single snapshot collection cycle.
// Exported for use in integration tests.
func (c *Collector) CollectOnce(ctx context.Context) {
	c.collect(ctx)
}

// collect performs a single snapshot collection cycle.
func (c *Collector) collect(ctx context.Context) {
	if err := c.ensurePreviousNodesLoaded(ctx); err != nil {
		c.logger.Warnf("[metering] failed to hydrate previous node state: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	c.logger.Infof("[metering] starting collection at %s", now.Format(time.RFC3339))

	c.maybeRunRetentionCleanup(ctx, now)

	controllerData := c.provider.FetchAllClusters()
	if len(controllerData) == 0 {
		c.logger.Warn("[metering] no controllers returned data")
		c.setCollectionError(ctx, "no controllers returned data")
		return
	}

	var snapshots []NodeSnapshot
	currentNodes := make(map[string]bool)
	controllerErrors := 0

	for addr, data := range controllerData {
		controllerID, err := c.resolveControllerID(ctx, addr, data.ControllerID)
		if err != nil {
			c.logger.Warnf("[metering] failed to resolve controller identity for %s: %v", addr, err)
			controllerID = addr
		}

		if data.Err != nil {
			controllerErrors++
			c.logger.Warnf("[metering] controller %s returned error: %v (skipping, not marking nodes removed)", addr, data.Err)
			// Preserve previous node set for this controller — don't mark as removed.
			c.mu.Lock()
			for nodeID := range c.previousNodes {
				// Keep nodes from errored controllers in the "previous" set.
				// A simple prefix check identifies which nodes belong to this controller.
				if len(nodeID) > len(controllerID) && nodeID[:len(controllerID)+1] == controllerID+":" {
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

				nodeID := fmt.Sprintf("%s:%s", controllerID, host.IP)
				currentNodes[nodeID] = true

				status := nodeStatusFromHostStatus(host.HostStatus)

				snap := NodeSnapshot{
					CapturedAt:   now,
					ControllerID: controllerID,
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

				// Attach hardware stats if available.
				if data.HostStats != nil {
					if hw, ok := data.HostStats[host.HostID]; ok && hw != nil {
						snap.RAMMB = hw.RAMMB
						snap.VolumeGB = hw.VolumeGB
					}
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
		c.recordCollectionSuccess(ctx, now, controllerErrors)
		return
	}

	if err := c.storage.InsertSnapshots(ctx, snapshots); err != nil {
		c.logger.Errorf("[metering] failed to insert %d snapshots: %v", len(snapshots), err)
		c.setCollectionError(ctx, fmt.Sprintf("failed to insert %d snapshots: %v", len(snapshots), err))
		return
	}

	c.recordCollectionSuccess(ctx, now, controllerErrors)
	c.logger.Infof("[metering] collected %d snapshots", len(snapshots))
}

func (c *Collector) ensurePreviousNodesLoaded(ctx context.Context) error {
	c.mu.Lock()
	if c.hydrated {
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()

	nodeIDs, err := c.storage.ListActiveNodeIDs(ctx)
	if err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.hydrated {
		return nil
	}
	for _, nodeID := range nodeIDs {
		c.previousNodes[nodeID] = true
	}
	c.hydrated = true
	return nil
}

func (c *Collector) resolveControllerID(ctx context.Context, addr, discovered string) (string, error) {
	c.mu.Lock()
	if controllerID, ok := c.controllerIDs[addr]; ok {
		c.mu.Unlock()
		return controllerID, nil
	}
	c.mu.Unlock()

	key := controllerIdentityConfigPrefix + addr
	if stored, err := c.storage.GetConfig(ctx, key); err != nil {
		return "", err
	} else if stored != "" {
		c.mu.Lock()
		c.controllerIDs[addr] = stored
		c.mu.Unlock()
		return stored, nil
	}

	controllerID := discovered
	if controllerID == "" {
		controllerID = addr
	}
	if err := c.storage.SetConfig(ctx, key, controllerID); err != nil {
		return "", err
	}

	c.mu.Lock()
	c.controllerIDs[addr] = controllerID
	c.mu.Unlock()
	return controllerID, nil
}

func (c *Collector) recordCollectionSuccess(ctx context.Context, now time.Time, controllerErrors int) {
	if err := c.storage.SetConfig(ctx, ConfigLastSuccessfulCollection, now.Format(time.RFC3339)); err != nil {
		c.logger.Warnf("[metering] failed to update last collection time: %v", err)
	}

	if controllerErrors > 0 {
		c.setCollectionError(ctx, fmt.Sprintf("%d controller(s) returned errors during the last collection", controllerErrors))
		return
	}

	if err := c.storage.SetConfig(ctx, ConfigLastCollectionError, ""); err != nil {
		c.logger.Warnf("[metering] failed to clear last collection error: %v", err)
	}
}

func (c *Collector) setCollectionError(ctx context.Context, message string) {
	if err := c.storage.SetConfig(ctx, ConfigLastCollectionError, message); err != nil {
		c.logger.Warnf("[metering] failed to persist last collection error %q: %v", message, err)
	}
}

func (c *Collector) maybeRunRetentionCleanup(ctx context.Context, now time.Time) {
	lastCleanup, err := c.storage.GetConfig(ctx, ConfigLastRetentionCleanup)
	if err != nil {
		c.logger.Warnf("[metering] failed to read last retention cleanup time: %v", err)
		return
	}

	if lastCleanup != "" {
		lastCleanupAt, err := parseTimestamp(lastCleanup)
		if err == nil && now.Sub(lastCleanupAt) < 24*time.Hour {
			return
		}
	}

	retentionMonths := DefaultRetentionMonths
	if raw, err := c.storage.GetConfig(ctx, ConfigRetentionMonths); err != nil {
		c.logger.Warnf("[metering] failed to read retention setting: %v", err)
	} else if raw != "" {
		if parsed, err := strconv.Atoi(raw); err != nil {
			c.logger.Warnf("[metering] invalid retention_months value %q: %v", raw, err)
		} else if parsed > 0 {
			retentionMonths = parsed
		}
	}

	cutoff := now.AddDate(0, -retentionMonths, 0)
	deletedRows, err := c.storage.DeleteSnapshotsBefore(ctx, cutoff)
	if err != nil {
		c.logger.Warnf("[metering] retention cleanup failed: %v", err)
		if err := c.storage.SetConfig(ctx, ConfigLastCleanupError, err.Error()); err != nil {
			c.logger.Warnf("[metering] failed to persist cleanup error: %v", err)
		}
		return
	}

	if err := c.storage.SetConfig(ctx, ConfigLastRetentionCleanup, now.Format(time.RFC3339)); err != nil {
		c.logger.Warnf("[metering] failed to persist last cleanup time: %v", err)
	}
	if err := c.storage.SetConfig(ctx, ConfigLastCleanupDeletedRows, strconv.FormatInt(deletedRows, 10)); err != nil {
		c.logger.Warnf("[metering] failed to persist cleanup row count: %v", err)
	}
	if err := c.storage.SetConfig(ctx, ConfigLastCleanupError, ""); err != nil {
		c.logger.Warnf("[metering] failed to clear cleanup error: %v", err)
	}

	c.logger.Infof("[metering] retention cleanup completed: deleted %d snapshots older than %s", deletedRows, cutoff.Format(time.RFC3339))
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
