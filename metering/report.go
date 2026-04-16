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
	"sort"
	"time"
)

// ReportData is the top-level structure of a billing report's JSON payload.
type ReportData struct {
	ReportVersion    int                 `json:"report_version"`
	PeriodStart      string              `json:"period_start"`
	PeriodEnd        string              `json:"period_end"`
	GeneratedAt      string              `json:"generated_at"`
	Summary          ReportSummary       `json:"summary"`
	ByTypeAndVendor  []TypeVendorSummary `json:"by_type_and_vendor"`
	BillingTableRows []BillingTableRow   `json:"billing_table_rows"`
	NodeDetails      []NodeDetail        `json:"node_details"`
}

// ReportSummary holds the estate-wide totals.
type ReportSummary struct {
	TotalBillableNodes    int `json:"total_billable_nodes"`
	GrandTotalMaxVCPU     int `json:"grand_total_max_vcpu"`
	GrandTotalMaxRAMGB    int `json:"grand_total_max_ram_gb"`
	GrandTotalMaxVolumeGB int `json:"grand_total_max_volume_gb"`
}

// TypeVendorSummary holds per cluster-type + vendor aggregation.
type TypeVendorSummary struct {
	ClusterType        string `json:"cluster_type"`
	DBVendor           string `json:"db_vendor"`
	MaxConcurrentNodes int    `json:"max_concurrent_nodes"`
	MaxVCPU            int    `json:"max_vcpu"`
	MaxRAMGB           int    `json:"max_ram_gb"`
	MaxVolumeGB        int    `json:"max_volume_gb"`
}

// BillingTableRow represents a row in the export-oriented billing breakdown table.
type BillingTableRow struct {
	RowType            string `json:"row_type"`
	DeploymentType     string `json:"deployment_type"`
	Vendor             string `json:"vendor"`
	MaxConcurrentNodes int    `json:"max_concurrent_nodes"`
	MaxVCPU            int    `json:"max_vcpu"`
	MaxRAMGB           int    `json:"max_ram_gb"`
	MaxVolumeGB        int    `json:"max_volume_gb"`
}

// NodeDetail holds per-node billing details.
type NodeDetail struct {
	NodeID              string           `json:"node_id"`
	ControllerID        string           `json:"controller_id"`
	ClusterID           uint64           `json:"cluster_id"`
	ClusterName         string           `json:"cluster_name"`
	ClusterType         string           `json:"cluster_type"`
	DBVendor            string           `json:"db_vendor"`
	NodeRole            string           `json:"node_role"`
	ActiveHours         int              `json:"active_hours"`
	MaxVCPU             int              `json:"max_vcpu"`
	MaxVCPUObservedAt   string           `json:"max_vcpu_observed_at,omitempty"`
	MaxRAMMB            int              `json:"max_ram_mb"`
	MaxRAMObservedAt    string           `json:"max_ram_observed_at,omitempty"`
	MaxVolumeGB         int              `json:"max_volume_gb"`
	MaxVolumeObservedAt string           `json:"max_volume_observed_at,omitempty"`
	ResourceChanges     []ResourceChange `json:"resource_changes,omitempty"`
}

// ResourceChange records a change in a node's resources between consecutive snapshots.
type ResourceChange struct {
	At    string `json:"at"`
	Field string `json:"field"` // "vcpu", "ram_mb", "volume_gb"
	From  int    `json:"from"`
	To    int    `json:"to"`
}

// ReportGenerator computes billing reports from raw snapshot data.
type ReportGenerator struct {
	storage            StorageBackend
	minActiveDuration  time.Duration
	collectionInterval time.Duration
}

// NewReportGenerator creates a report generator.
func NewReportGenerator(storage StorageBackend, minActiveHours int, collectionInterval time.Duration) *ReportGenerator {
	if collectionInterval <= 0 {
		collectionInterval = time.Hour
	}
	return &ReportGenerator{
		storage:            storage,
		minActiveDuration:  time.Duration(minActiveHours) * time.Hour,
		collectionInterval: collectionInterval,
	}
}

// Generate computes a billing report for the given period.
func (g *ReportGenerator) Generate(ctx context.Context, periodStart, periodEnd time.Time, version int) (*ReportData, error) {
	now := time.Now().UTC()

	// Step 1: Fetch all snapshots for the period.
	snapshots, err := g.storage.QuerySnapshots(ctx, SnapshotFilter{
		PeriodStart: &periodStart,
		PeriodEnd:   &periodEnd,
	})
	if err != nil {
		return nil, err
	}

	if len(snapshots) == 0 {
		return &ReportData{
			ReportVersion:    version,
			PeriodStart:      periodStart.Format(time.RFC3339),
			PeriodEnd:        periodEnd.Format(time.RFC3339),
			GeneratedAt:      now.Format(time.RFC3339),
			ByTypeAndVendor:  []TypeVendorSummary{},
			BillingTableRows: []BillingTableRow{},
			NodeDetails:      []NodeDetail{},
		}, nil
	}

	// Group snapshots by node.
	nodeSnapshots := make(map[string][]NodeSnapshot)
	for _, s := range snapshots {
		nodeSnapshots[s.NodeID] = append(nodeSnapshots[s.NodeID], s)
	}

	// Step 2: Identify billable nodes (≥ minActiveHours of active/stopped time).
	billableNodes := make(map[string][]NodeSnapshot)
	for nodeID, snaps := range nodeSnapshots {
		activeDuration := activeDurationForSnapshots(snaps, g.collectionInterval)
		if activeDuration >= g.minActiveDuration {
			billableNodes[nodeID] = snaps
		}
	}

	// Step 3: Compute per-node details.
	var nodeDetails []NodeDetail
	for nodeID, snaps := range billableNodes {
		detail := computeNodeDetail(nodeID, snaps, g.collectionInterval)
		nodeDetails = append(nodeDetails, detail)
	}

	// Sort node details by node_id for deterministic output.
	sort.Slice(nodeDetails, func(i, j int) bool {
		return nodeDetails[i].NodeID < nodeDetails[j].NodeID
	})

	// Step 4: Compute by-type-and-vendor summary (max concurrent nodes).
	byTypeVendor := computeTypeVendorSummary(snapshots, billableNodes)

	// Step 5: Compute grand totals.
	summary := computeSummary(nodeDetails)
	billingTableRows := computeBillingTableRows(snapshots, billableNodes, byTypeVendor, summary)

	return &ReportData{
		ReportVersion:    version,
		PeriodStart:      periodStart.Format(time.RFC3339),
		PeriodEnd:        periodEnd.Format(time.RFC3339),
		GeneratedAt:      now.Format(time.RFC3339),
		Summary:          summary,
		ByTypeAndVendor:  byTypeVendor,
		BillingTableRows: billingTableRows,
		NodeDetails:      nodeDetails,
	}, nil
}

func activeDurationForSnapshots(snaps []NodeSnapshot, interval time.Duration) time.Duration {
	var activeDuration time.Duration
	for _, s := range snaps {
		if s.NodeStatus == NodeStatusActive || s.NodeStatus == NodeStatusStopped {
			activeDuration += interval
		}
	}
	return activeDuration
}

// computeNodeDetail computes billing details for a single node.
func computeNodeDetail(nodeID string, snaps []NodeSnapshot, collectionInterval time.Duration) NodeDetail {
	// Sort by captured_at for resource change detection.
	sort.Slice(snaps, func(i, j int) bool {
		return snaps[i].CapturedAt.Before(snaps[j].CapturedAt)
	})

	// Use the first snapshot with full metadata for identity fields.
	// (Removed-status snapshots may have minimal fields.)
	var ref NodeSnapshot
	for _, s := range snaps {
		if s.NodeStatus != NodeStatusRemoved {
			ref = s
			break
		}
	}
	if ref.NodeID == "" {
		ref = snaps[0]
	}

	activeDuration := activeDurationForSnapshots(snaps, collectionInterval)
	activeHours := int(activeDuration / time.Hour)
	var maxVCPU, maxRAM, maxVol int
	var maxVCPUAt, maxRAMAt, maxVolAt string
	var changes []ResourceChange

	var prevVCPU, prevRAM, prevVol *int

	for _, s := range snaps {
		ts := s.CapturedAt.Format(time.RFC3339)

		// Track high-water marks.
		if s.VCPU != nil {
			if *s.VCPU > maxVCPU {
				maxVCPU = *s.VCPU
				maxVCPUAt = ts
			}
		}
		if s.RAMMB != nil {
			if *s.RAMMB > maxRAM {
				maxRAM = *s.RAMMB
				maxRAMAt = ts
			}
		}
		if s.VolumeGB != nil {
			if *s.VolumeGB > maxVol {
				maxVol = *s.VolumeGB
				maxVolAt = ts
			}
		}

		// Detect resource changes.
		if prevVCPU != nil && s.VCPU != nil && *s.VCPU != *prevVCPU {
			changes = append(changes, ResourceChange{At: ts, Field: "vcpu", From: *prevVCPU, To: *s.VCPU})
		}
		if prevRAM != nil && s.RAMMB != nil && *s.RAMMB != *prevRAM {
			changes = append(changes, ResourceChange{At: ts, Field: "ram_mb", From: *prevRAM, To: *s.RAMMB})
		}
		if prevVol != nil && s.VolumeGB != nil && *s.VolumeGB != *prevVol {
			changes = append(changes, ResourceChange{At: ts, Field: "volume_gb", From: *prevVol, To: *s.VolumeGB})
		}

		prevVCPU = s.VCPU
		prevRAM = s.RAMMB
		prevVol = s.VolumeGB
	}

	return NodeDetail{
		NodeID:              nodeID,
		ControllerID:        ref.ControllerID,
		ClusterID:           ref.ClusterID,
		ClusterName:         ref.ClusterName,
		ClusterType:         ref.ClusterType,
		DBVendor:            ref.DBVendor,
		NodeRole:            ref.NodeRole,
		ActiveHours:         activeHours,
		MaxVCPU:             maxVCPU,
		MaxVCPUObservedAt:   maxVCPUAt,
		MaxRAMMB:            maxRAM,
		MaxRAMObservedAt:    maxRAMAt,
		MaxVolumeGB:         maxVol,
		MaxVolumeObservedAt: maxVolAt,
		ResourceChanges:     changes,
	}
}

// computeTypeVendorSummary computes max concurrent nodes and resource high-water marks
// per cluster type + vendor combination.
func computeTypeVendorSummary(allSnapshots []NodeSnapshot, billableNodes map[string][]NodeSnapshot) []TypeVendorSummary {
	billableSet := make(map[string]bool)
	for nodeID := range billableNodes {
		billableSet[nodeID] = true
	}

	// Group snapshots by (captured_at, cluster_type, db_vendor) to count concurrency.
	type tvKey struct {
		ClusterType string
		DBVendor    string
	}
	type tsKey struct {
		CapturedAt  time.Time
		ClusterType string
		DBVendor    string
	}

	// Count concurrent active billable nodes per timestamp per type+vendor.
	concurrency := make(map[tsKey]int)
	for _, s := range allSnapshots {
		if !billableSet[s.NodeID] {
			continue
		}
		if s.NodeStatus != NodeStatusActive {
			continue
		}
		key := tsKey{CapturedAt: s.CapturedAt, ClusterType: s.ClusterType, DBVendor: s.DBVendor}
		concurrency[key]++
	}

	// Find max concurrency per type+vendor.
	maxConcurrent := make(map[tvKey]int)
	for key, count := range concurrency {
		tv := tvKey{ClusterType: key.ClusterType, DBVendor: key.DBVendor}
		if count > maxConcurrent[tv] {
			maxConcurrent[tv] = count
		}
	}

	// Compute resource high-water marks per type+vendor from billable nodes.
	tvMaxVCPU := make(map[tvKey]int)
	tvMaxRAM := make(map[tvKey]int)
	tvMaxVol := make(map[tvKey]int)

	for _, snaps := range billableNodes {
		if len(snaps) == 0 {
			continue
		}
		// Use the reference snapshot for type+vendor classification.
		var ref NodeSnapshot
		for _, s := range snaps {
			if s.NodeStatus != NodeStatusRemoved {
				ref = s
				break
			}
		}
		if ref.NodeID == "" {
			ref = snaps[0]
		}

		tv := tvKey{ClusterType: ref.ClusterType, DBVendor: ref.DBVendor}

		for _, s := range snaps {
			if s.VCPU != nil && *s.VCPU > tvMaxVCPU[tv] {
				tvMaxVCPU[tv] = *s.VCPU
			}
			if s.RAMMB != nil && *s.RAMMB > tvMaxRAM[tv] {
				tvMaxRAM[tv] = *s.RAMMB
			}
			if s.VolumeGB != nil && *s.VolumeGB > tvMaxVol[tv] {
				tvMaxVol[tv] = *s.VolumeGB
			}
		}
	}

	// Collect all type+vendor keys.
	allKeys := make(map[tvKey]bool)
	for k := range maxConcurrent {
		allKeys[k] = true
	}
	for k := range tvMaxVCPU {
		allKeys[k] = true
	}

	var results []TypeVendorSummary
	for tv := range allKeys {
		results = append(results, TypeVendorSummary{
			ClusterType:        tv.ClusterType,
			DBVendor:           tv.DBVendor,
			MaxConcurrentNodes: maxConcurrent[tv],
			MaxVCPU:            tvMaxVCPU[tv],
			MaxRAMGB:           tvMaxRAM[tv] / 1024, // MB to GB
			MaxVolumeGB:        tvMaxVol[tv],
		})
	}

	// Sort for deterministic output.
	sort.Slice(results, func(i, j int) bool {
		if results[i].ClusterType != results[j].ClusterType {
			return results[i].ClusterType < results[j].ClusterType
		}
		return results[i].DBVendor < results[j].DBVendor
	})

	return results
}

// computeSummary computes the estate-wide totals from node details.
func computeSummary(details []NodeDetail) ReportSummary {
	s := ReportSummary{
		TotalBillableNodes: len(details),
	}
	for _, d := range details {
		s.GrandTotalMaxVCPU += d.MaxVCPU
		s.GrandTotalMaxRAMGB += d.MaxRAMMB / 1024 // MB to GB
		s.GrandTotalMaxVolumeGB += d.MaxVolumeGB
	}
	return s
}

func computeBillingTableRows(allSnapshots []NodeSnapshot, billableNodes map[string][]NodeSnapshot, byTypeVendor []TypeVendorSummary, summary ReportSummary) []BillingTableRow {
	rows := make([]BillingTableRow, 0, len(byTypeVendor)+1)
	totalsByType := make(map[string]BillingTableRow)
	maxConcurrentByType := make(map[string]int)
	maxConcurrentAll := 0

	billableSet := make(map[string]bool, len(billableNodes))
	for nodeID := range billableNodes {
		billableSet[nodeID] = true
	}

	typeConcurrency := make(map[string]map[time.Time]int)
	allConcurrency := make(map[time.Time]int)
	for _, snapshot := range allSnapshots {
		if !billableSet[snapshot.NodeID] || snapshot.NodeStatus != NodeStatusActive {
			continue
		}
		if _, ok := typeConcurrency[snapshot.ClusterType]; !ok {
			typeConcurrency[snapshot.ClusterType] = make(map[time.Time]int)
		}
		typeConcurrency[snapshot.ClusterType][snapshot.CapturedAt]++
		allConcurrency[snapshot.CapturedAt]++
	}

	for clusterType, counts := range typeConcurrency {
		for _, count := range counts {
			if count > maxConcurrentByType[clusterType] {
				maxConcurrentByType[clusterType] = count
			}
		}
	}
	for _, count := range allConcurrency {
		if count > maxConcurrentAll {
			maxConcurrentAll = count
		}
	}

	for _, item := range byTypeVendor {
		rows = append(rows, BillingTableRow{
			RowType:            "vendor",
			DeploymentType:     item.ClusterType,
			Vendor:             item.DBVendor,
			MaxConcurrentNodes: item.MaxConcurrentNodes,
			MaxVCPU:            item.MaxVCPU,
			MaxRAMGB:           item.MaxRAMGB,
			MaxVolumeGB:        item.MaxVolumeGB,
		})

		total := totalsByType[item.ClusterType]
		total.RowType = "type_total"
		total.DeploymentType = item.ClusterType
		total.Vendor = "Total"
		total.MaxVCPU += item.MaxVCPU
		total.MaxRAMGB += item.MaxRAMGB
		total.MaxVolumeGB += item.MaxVolumeGB
		totalsByType[item.ClusterType] = total
	}

	if len(totalsByType) > 0 {
		typeNames := make([]string, 0, len(totalsByType))
		for clusterType := range totalsByType {
			typeNames = append(typeNames, clusterType)
		}
		sort.Strings(typeNames)

		withTotals := make([]BillingTableRow, 0, len(rows)+len(typeNames)+1)
		for _, clusterType := range typeNames {
			for _, row := range rows {
				if row.DeploymentType == clusterType {
					withTotals = append(withTotals, row)
				}
			}
			total := totalsByType[clusterType]
			total.MaxConcurrentNodes = maxConcurrentByType[clusterType]
			withTotals = append(withTotals, total)
		}
		rows = withTotals
	}

	rows = append(rows, BillingTableRow{
		RowType:            "grand_total",
		Vendor:             "Grand Total",
		MaxConcurrentNodes: maxConcurrentAll,
		MaxVCPU:            summary.GrandTotalMaxVCPU,
		MaxRAMGB:           summary.GrandTotalMaxRAMGB,
		MaxVolumeGB:        summary.GrandTotalMaxVolumeGB,
	})

	return rows
}
