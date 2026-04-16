package metering

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newReportTestBackend(t *testing.T) *SQLiteBackend {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "report_test.db")
	backend, err := NewSQLiteBackend(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { backend.Close() })
	return backend
}

// seedSnapshots inserts hourly snapshots for a set of nodes over a given hour range.
func seedSnapshots(t *testing.T, backend *SQLiteBackend, start time.Time, hours int, nodes []NodeSnapshot) {
	t.Helper()
	ctx := context.Background()
	for h := 0; h < hours; h++ {
		ts := start.Add(time.Duration(h) * time.Hour)
		var batch []NodeSnapshot
		for _, n := range nodes {
			snap := n
			snap.CapturedAt = ts
			batch = append(batch, snap)
		}
		require.NoError(t, backend.InsertSnapshots(ctx, batch))
	}
}

func TestReportGenerator_EmptyPeriod(t *testing.T) {
	backend := newReportTestBackend(t)
	gen := NewReportGenerator(backend, 24)

	ctx := context.Background()
	start := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 4, 30, 23, 59, 59, 0, time.UTC)

	report, err := gen.Generate(ctx, start, end, 1)
	require.NoError(t, err)
	assert.Equal(t, 1, report.ReportVersion)
	assert.Equal(t, 0, report.Summary.TotalBillableNodes)
	assert.Empty(t, report.NodeDetails)
	assert.Empty(t, report.ByTypeAndVendor)
}

func TestReportGenerator_BillableThreshold(t *testing.T) {
	backend := newReportTestBackend(t)
	gen := NewReportGenerator(backend, 24)
	ctx := context.Background()

	start := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 4, 30, 23, 59, 59, 0, time.UTC)

	// Node A: 30 hours active — should be billable.
	nodeA := NodeSnapshot{
		ControllerID: "ctrl-1", ClusterID: 1, ClusterName: "prod", ClusterType: "galera",
		DBVendor: "percona", NodeID: "ctrl-1:10.0.1.1", Hostname: "db1", Port: 3306,
		NodeRole: NodeRoleDatabase, NodeStatus: NodeStatusActive,
		VCPU: intPtr(4), RAMMB: intPtr(8192), VolumeGB: intPtr(100),
	}
	// Node B: 20 hours active — should NOT be billable.
	nodeB := NodeSnapshot{
		ControllerID: "ctrl-1", ClusterID: 1, ClusterName: "prod", ClusterType: "galera",
		DBVendor: "percona", NodeID: "ctrl-1:10.0.1.2", Hostname: "db2", Port: 3306,
		NodeRole: NodeRoleDatabase, NodeStatus: NodeStatusActive,
		VCPU: intPtr(4), RAMMB: intPtr(8192), VolumeGB: intPtr(100),
	}

	seedSnapshots(t, backend, start, 30, []NodeSnapshot{nodeA})
	seedSnapshots(t, backend, start, 20, []NodeSnapshot{nodeB})

	report, err := gen.Generate(ctx, start, end, 1)
	require.NoError(t, err)

	assert.Equal(t, 1, report.Summary.TotalBillableNodes)
	assert.Len(t, report.NodeDetails, 1)
	assert.Equal(t, "ctrl-1:10.0.1.1", report.NodeDetails[0].NodeID)
	assert.Equal(t, 30, report.NodeDetails[0].ActiveHours)
}

func TestReportGenerator_StoppedNodesCounted(t *testing.T) {
	backend := newReportTestBackend(t)
	gen := NewReportGenerator(backend, 24)
	ctx := context.Background()

	start := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 4, 30, 23, 59, 59, 0, time.UTC)

	// Node with 12 hours active + 15 hours stopped = 27 total → billable.
	node := NodeSnapshot{
		ControllerID: "ctrl-1", ClusterID: 1, ClusterName: "prod", ClusterType: "galera",
		DBVendor: "percona", NodeID: "ctrl-1:10.0.1.1", Hostname: "db1", Port: 3306,
		NodeRole: NodeRoleDatabase, NodeStatus: NodeStatusActive,
		VCPU: intPtr(4), RAMMB: intPtr(8192),
	}

	// 12 hours active
	seedSnapshots(t, backend, start, 12, []NodeSnapshot{node})

	// 15 hours stopped
	stoppedNode := node
	stoppedNode.NodeStatus = NodeStatusStopped
	seedSnapshots(t, backend, start.Add(12*time.Hour), 15, []NodeSnapshot{stoppedNode})

	report, err := gen.Generate(ctx, start, end, 1)
	require.NoError(t, err)

	assert.Equal(t, 1, report.Summary.TotalBillableNodes)
	assert.Equal(t, 27, report.NodeDetails[0].ActiveHours)
}

func TestReportGenerator_HighWaterMarks(t *testing.T) {
	backend := newReportTestBackend(t)
	gen := NewReportGenerator(backend, 1) // low threshold for testing
	ctx := context.Background()

	start := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 4, 30, 23, 59, 59, 0, time.UTC)

	// Start with 4 vCPU, scale up to 8, then back to 4.
	baseNode := NodeSnapshot{
		ControllerID: "ctrl-1", ClusterID: 1, ClusterName: "prod", ClusterType: "galera",
		DBVendor: "percona", NodeID: "ctrl-1:10.0.1.1", Hostname: "db1", Port: 3306,
		NodeRole: NodeRoleDatabase, NodeStatus: NodeStatusActive,
		VCPU: intPtr(4), RAMMB: intPtr(8192), VolumeGB: intPtr(100),
	}

	// Hours 0-9: 4 vCPU
	seedSnapshots(t, backend, start, 10, []NodeSnapshot{baseNode})

	// Hours 10-14: 8 vCPU (scale up)
	scaledUp := baseNode
	scaledUp.VCPU = intPtr(8)
	seedSnapshots(t, backend, start.Add(10*time.Hour), 5, []NodeSnapshot{scaledUp})

	// Hours 15-24: 4 vCPU (scale down)
	seedSnapshots(t, backend, start.Add(15*time.Hour), 10, []NodeSnapshot{baseNode})

	report, err := gen.Generate(ctx, start, end, 1)
	require.NoError(t, err)

	require.Len(t, report.NodeDetails, 1)
	detail := report.NodeDetails[0]

	// High-water mark should be 8 vCPU.
	assert.Equal(t, 8, detail.MaxVCPU)
	assert.Equal(t, start.Add(10*time.Hour).Format(time.RFC3339), detail.MaxVCPUObservedAt)
	assert.Equal(t, 8192, detail.MaxRAMMB)
	assert.Equal(t, 100, detail.MaxVolumeGB)

	// Should detect resource changes: 4→8 at hour 10, 8→4 at hour 15.
	require.Len(t, detail.ResourceChanges, 2)
	assert.Equal(t, "vcpu", detail.ResourceChanges[0].Field)
	assert.Equal(t, 4, detail.ResourceChanges[0].From)
	assert.Equal(t, 8, detail.ResourceChanges[0].To)
	assert.Equal(t, "vcpu", detail.ResourceChanges[1].Field)
	assert.Equal(t, 8, detail.ResourceChanges[1].From)
	assert.Equal(t, 4, detail.ResourceChanges[1].To)
}

func TestReportGenerator_MaxConcurrentNodes(t *testing.T) {
	backend := newReportTestBackend(t)
	gen := NewReportGenerator(backend, 1) // low threshold
	ctx := context.Background()

	start := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 4, 30, 23, 59, 59, 0, time.UTC)

	node1 := NodeSnapshot{
		ControllerID: "ctrl-1", ClusterID: 1, ClusterName: "prod", ClusterType: "galera",
		DBVendor: "percona", NodeID: "ctrl-1:10.0.1.1", Hostname: "db1", Port: 3306,
		NodeRole: NodeRoleDatabase, NodeStatus: NodeStatusActive,
		VCPU: intPtr(4), RAMMB: intPtr(8192),
	}
	node2 := NodeSnapshot{
		ControllerID: "ctrl-1", ClusterID: 1, ClusterName: "prod", ClusterType: "galera",
		DBVendor: "percona", NodeID: "ctrl-1:10.0.1.2", Hostname: "db2", Port: 3306,
		NodeRole: NodeRoleDatabase, NodeStatus: NodeStatusActive,
		VCPU: intPtr(4), RAMMB: intPtr(8192),
	}
	node3 := NodeSnapshot{
		ControllerID: "ctrl-1", ClusterID: 1, ClusterName: "prod", ClusterType: "galera",
		DBVendor: "percona", NodeID: "ctrl-1:10.0.1.3", Hostname: "db3", Port: 3306,
		NodeRole: NodeRoleDatabase, NodeStatus: NodeStatusActive,
		VCPU: intPtr(4), RAMMB: intPtr(8192),
	}

	// Hours 0-4: 2 nodes active
	seedSnapshots(t, backend, start, 5, []NodeSnapshot{node1, node2})

	// Hours 5-9: 3 nodes active (peak concurrency)
	seedSnapshots(t, backend, start.Add(5*time.Hour), 5, []NodeSnapshot{node1, node2, node3})

	// Hours 10-14: back to 2 nodes
	seedSnapshots(t, backend, start.Add(10*time.Hour), 5, []NodeSnapshot{node1, node2})

	report, err := gen.Generate(ctx, start, end, 1)
	require.NoError(t, err)

	assert.Equal(t, 3, report.Summary.TotalBillableNodes)

	require.Len(t, report.ByTypeAndVendor, 1)
	assert.Equal(t, "galera", report.ByTypeAndVendor[0].ClusterType)
	assert.Equal(t, "percona", report.ByTypeAndVendor[0].DBVendor)
	assert.Equal(t, 3, report.ByTypeAndVendor[0].MaxConcurrentNodes)
}

func TestReportGenerator_MultipleTypeVendor(t *testing.T) {
	backend := newReportTestBackend(t)
	gen := NewReportGenerator(backend, 1) // low threshold
	ctx := context.Background()

	start := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 4, 30, 23, 59, 59, 0, time.UTC)

	galeraNode := NodeSnapshot{
		ControllerID: "ctrl-1", ClusterID: 1, ClusterName: "prod-galera", ClusterType: "galera",
		DBVendor: "percona", NodeID: "ctrl-1:10.0.1.1", Hostname: "db1", Port: 3306,
		NodeRole: NodeRoleDatabase, NodeStatus: NodeStatusActive,
		VCPU: intPtr(8), RAMMB: intPtr(16384), VolumeGB: intPtr(200),
	}
	pgNode := NodeSnapshot{
		ControllerID: "ctrl-1", ClusterID: 2, ClusterName: "prod-pg", ClusterType: "postgresql",
		DBVendor: "postgresql", NodeID: "ctrl-1:10.0.2.1", Hostname: "pg1", Port: 5432,
		NodeRole: NodeRoleDatabase, NodeStatus: NodeStatusActive,
		VCPU: intPtr(4), RAMMB: intPtr(8192), VolumeGB: intPtr(500),
	}

	seedSnapshots(t, backend, start, 48, []NodeSnapshot{galeraNode, pgNode})

	report, err := gen.Generate(ctx, start, end, 1)
	require.NoError(t, err)

	assert.Equal(t, 2, report.Summary.TotalBillableNodes)
	assert.Len(t, report.ByTypeAndVendor, 2)

	// Sorted by cluster_type: galera before postgresql.
	assert.Equal(t, "galera", report.ByTypeAndVendor[0].ClusterType)
	assert.Equal(t, "percona", report.ByTypeAndVendor[0].DBVendor)
	assert.Equal(t, 1, report.ByTypeAndVendor[0].MaxConcurrentNodes)
	assert.Equal(t, 8, report.ByTypeAndVendor[0].MaxVCPU)

	assert.Equal(t, "postgresql", report.ByTypeAndVendor[1].ClusterType)
	assert.Equal(t, 1, report.ByTypeAndVendor[1].MaxConcurrentNodes)
	assert.Equal(t, 500, report.ByTypeAndVendor[1].MaxVolumeGB)
}

func TestReportGenerator_RemovedNodesExcluded(t *testing.T) {
	backend := newReportTestBackend(t)
	gen := NewReportGenerator(backend, 24)
	ctx := context.Background()

	start := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 4, 30, 23, 59, 59, 0, time.UTC)

	node := NodeSnapshot{
		ControllerID: "ctrl-1", ClusterID: 1, ClusterName: "prod", ClusterType: "galera",
		DBVendor: "percona", NodeID: "ctrl-1:10.0.1.1", Hostname: "db1", Port: 3306,
		NodeRole: NodeRoleDatabase, NodeStatus: NodeStatusActive,
		VCPU: intPtr(4), RAMMB: intPtr(8192),
	}

	// 20 hours active then removed — "removed" snapshots don't count toward 24h.
	seedSnapshots(t, backend, start, 20, []NodeSnapshot{node})

	removedNode := NodeSnapshot{
		ControllerID: "ctrl-1", NodeID: "ctrl-1:10.0.1.1",
		NodeRole: NodeRoleDatabase, NodeStatus: NodeStatusRemoved,
	}
	seedSnapshots(t, backend, start.Add(20*time.Hour), 10, []NodeSnapshot{removedNode})

	report, err := gen.Generate(ctx, start, end, 1)
	require.NoError(t, err)

	// Only 20 active hours, so not billable.
	assert.Equal(t, 0, report.Summary.TotalBillableNodes)
}

func TestReportGenerator_Exactly24Hours(t *testing.T) {
	backend := newReportTestBackend(t)
	gen := NewReportGenerator(backend, 24)
	ctx := context.Background()

	start := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 4, 30, 23, 59, 59, 0, time.UTC)

	node := NodeSnapshot{
		ControllerID: "ctrl-1", ClusterID: 1, ClusterName: "prod", ClusterType: "galera",
		DBVendor: "percona", NodeID: "ctrl-1:10.0.1.1", Hostname: "db1", Port: 3306,
		NodeRole: NodeRoleDatabase, NodeStatus: NodeStatusActive,
		VCPU: intPtr(4), RAMMB: intPtr(8192),
	}

	// Exactly 24 hours — should be billable (>= threshold).
	seedSnapshots(t, backend, start, 24, []NodeSnapshot{node})

	report, err := gen.Generate(ctx, start, end, 1)
	require.NoError(t, err)

	assert.Equal(t, 1, report.Summary.TotalBillableNodes)
}

func TestReportGenerator_SummaryTotals(t *testing.T) {
	backend := newReportTestBackend(t)
	gen := NewReportGenerator(backend, 1) // low threshold
	ctx := context.Background()

	start := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 4, 30, 23, 59, 59, 0, time.UTC)

	node1 := NodeSnapshot{
		ControllerID: "ctrl-1", ClusterID: 1, ClusterName: "prod", ClusterType: "galera",
		DBVendor: "percona", NodeID: "ctrl-1:10.0.1.1", Hostname: "db1", Port: 3306,
		NodeRole: NodeRoleDatabase, NodeStatus: NodeStatusActive,
		VCPU: intPtr(8), RAMMB: intPtr(16384), VolumeGB: intPtr(200),
	}
	node2 := NodeSnapshot{
		ControllerID: "ctrl-1", ClusterID: 1, ClusterName: "prod", ClusterType: "galera",
		DBVendor: "percona", NodeID: "ctrl-1:10.0.1.2", Hostname: "db2", Port: 3306,
		NodeRole: NodeRoleDatabase, NodeStatus: NodeStatusActive,
		VCPU: intPtr(4), RAMMB: intPtr(8192), VolumeGB: intPtr(100),
	}

	seedSnapshots(t, backend, start, 5, []NodeSnapshot{node1, node2})

	report, err := gen.Generate(ctx, start, end, 1)
	require.NoError(t, err)

	assert.Equal(t, 2, report.Summary.TotalBillableNodes)
	assert.Equal(t, 12, report.Summary.GrandTotalMaxVCPU)       // 8 + 4
	assert.Equal(t, 24, report.Summary.GrandTotalMaxRAMGB)       // 16384/1024 + 8192/1024 = 16 + 8
	assert.Equal(t, 300, report.Summary.GrandTotalMaxVolumeGB)   // 200 + 100
}
