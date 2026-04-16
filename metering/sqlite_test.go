package metering

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestBackend(t *testing.T) *SQLiteBackend {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "metering_test.db")
	backend, err := NewSQLiteBackend(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { backend.Close() })
	return backend
}

func intPtr(v int) *int { return &v }

func TestNewSQLiteBackend_CreatesSchema(t *testing.T) {
	backend := newTestBackend(t)

	// Verify tables exist by running queries against them.
	ctx := context.Background()

	count, err := backend.CountSnapshots(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)

	reports, err := backend.ListReports(ctx)
	require.NoError(t, err)
	assert.Empty(t, reports)

	val, err := backend.GetConfig(ctx, "nonexistent")
	require.NoError(t, err)
	assert.Equal(t, "", val)
}

func TestNewSQLiteBackend_InvalidPath(t *testing.T) {
	_, err := NewSQLiteBackend("/nonexistent/path/db.sqlite")
	// Opening should succeed (sqlite creates the file), but the dir doesn't exist
	assert.Error(t, err)
}

func TestInsertAndQuerySnapshots(t *testing.T) {
	backend := newTestBackend(t)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Hour)

	snapshots := []NodeSnapshot{
		{
			CapturedAt:   now,
			ControllerID: "ctrl-1",
			ClusterID:    1,
			ClusterName:  "prod-galera",
			ClusterType:  "galera",
			DBVendor:     "percona",
			NodeID:       "ctrl-1:10.0.1.1",
			Hostname:     "db-node-1",
			Port:         3306,
			NodeRole:     NodeRoleDatabase,
			NodeStatus:   NodeStatusActive,
			VCPU:         intPtr(4),
			RAMMB:        intPtr(8192),
			VolumeGB:     intPtr(100),
			Tags:         []string{"customer-123", "env-prod"},
		},
		{
			CapturedAt:   now,
			ControllerID: "ctrl-1",
			ClusterID:    1,
			ClusterName:  "prod-galera",
			ClusterType:  "galera",
			DBVendor:     "percona",
			NodeID:       "ctrl-1:10.0.1.2",
			Hostname:     "db-node-2",
			Port:         3306,
			NodeRole:     NodeRoleDatabase,
			NodeStatus:   NodeStatusActive,
			VCPU:         intPtr(4),
			RAMMB:        intPtr(8192),
			VolumeGB:     intPtr(100),
			Tags:         []string{"customer-123"},
		},
		{
			CapturedAt:   now,
			ControllerID: "ctrl-1",
			ClusterID:    1,
			ClusterName:  "prod-galera",
			ClusterType:  "galera",
			DBVendor:     "percona",
			NodeID:       "ctrl-1:10.0.1.3",
			Hostname:     "proxy-1",
			Port:         6033,
			NodeRole:     NodeRoleProxySQL,
			NodeStatus:   NodeStatusActive,
			VCPU:         intPtr(2),
			RAMMB:        intPtr(4096),
			Tags:         []string{"customer-123"},
		},
	}

	err := backend.InsertSnapshots(ctx, snapshots)
	require.NoError(t, err)

	// Verify count.
	count, err := backend.CountSnapshots(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(3), count)

	// Query all.
	results, err := backend.QuerySnapshots(ctx, SnapshotFilter{})
	require.NoError(t, err)
	assert.Len(t, results, 3)

	// Verify fields of first result.
	assert.Equal(t, "ctrl-1:10.0.1.1", results[0].NodeID)
	assert.Equal(t, "prod-galera", results[0].ClusterName)
	assert.Equal(t, "galera", results[0].ClusterType)
	assert.Equal(t, "percona", results[0].DBVendor)
	assert.Equal(t, NodeRoleDatabase, results[0].NodeRole)
	assert.Equal(t, NodeStatusActive, results[0].NodeStatus)
	assert.Equal(t, intPtr(4), results[0].VCPU)
	assert.Equal(t, intPtr(8192), results[0].RAMMB)
	assert.Equal(t, intPtr(100), results[0].VolumeGB)
	assert.Equal(t, []string{"customer-123", "env-prod"}, results[0].Tags)

	// ProxySQL node has nil VolumeGB.
	assert.Nil(t, results[2].VolumeGB)
}

func TestQuerySnapshots_FilterByPeriod(t *testing.T) {
	backend := newTestBackend(t)
	ctx := context.Background()

	hour1 := time.Date(2026, 4, 1, 10, 0, 0, 0, time.UTC)
	hour2 := time.Date(2026, 4, 1, 11, 0, 0, 0, time.UTC)
	hour3 := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)

	for _, ts := range []time.Time{hour1, hour2, hour3} {
		err := backend.InsertSnapshots(ctx, []NodeSnapshot{{
			CapturedAt:   ts,
			ControllerID: "ctrl-1",
			ClusterID:    1,
			ClusterName:  "test",
			ClusterType:  "replication",
			DBVendor:     "oracle",
			NodeID:       "ctrl-1:10.0.0.1",
			Hostname:     "node-1",
			Port:         3306,
			NodeRole:     NodeRoleDatabase,
			NodeStatus:   NodeStatusActive,
		}})
		require.NoError(t, err)
	}

	// Filter to middle hour only.
	results, err := backend.QuerySnapshots(ctx, SnapshotFilter{
		PeriodStart: &hour2,
		PeriodEnd:   &hour2,
	})
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, hour2, results[0].CapturedAt)
}

func TestQuerySnapshots_FilterByStatus(t *testing.T) {
	backend := newTestBackend(t)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Hour)

	err := backend.InsertSnapshots(ctx, []NodeSnapshot{
		{CapturedAt: now, ControllerID: "c", ClusterID: 1, ClusterName: "x", ClusterType: "t", DBVendor: "v", NodeID: "c:1", Hostname: "h1", Port: 1, NodeRole: NodeRoleDatabase, NodeStatus: NodeStatusActive},
		{CapturedAt: now, ControllerID: "c", ClusterID: 1, ClusterName: "x", ClusterType: "t", DBVendor: "v", NodeID: "c:2", Hostname: "h2", Port: 1, NodeRole: NodeRoleDatabase, NodeStatus: NodeStatusStopped},
		{CapturedAt: now, ControllerID: "c", ClusterID: 1, ClusterName: "x", ClusterType: "t", DBVendor: "v", NodeID: "c:3", Hostname: "h3", Port: 1, NodeRole: NodeRoleDatabase, NodeStatus: NodeStatusRemoved},
	})
	require.NoError(t, err)

	// Filter active + stopped (billable statuses).
	results, err := backend.QuerySnapshots(ctx, SnapshotFilter{
		NodeStatuses: []string{NodeStatusActive, NodeStatusStopped},
	})
	require.NoError(t, err)
	assert.Len(t, results, 2)
}

func TestQuerySnapshots_FilterByNodeRole(t *testing.T) {
	backend := newTestBackend(t)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Hour)

	err := backend.InsertSnapshots(ctx, []NodeSnapshot{
		{CapturedAt: now, ControllerID: "c", ClusterID: 1, ClusterName: "x", ClusterType: "t", DBVendor: "v", NodeID: "c:1", Hostname: "h1", Port: 1, NodeRole: NodeRoleDatabase, NodeStatus: NodeStatusActive},
		{CapturedAt: now, ControllerID: "c", ClusterID: 1, ClusterName: "x", ClusterType: "t", DBVendor: "v", NodeID: "c:2", Hostname: "h2", Port: 1, NodeRole: NodeRoleProxySQL, NodeStatus: NodeStatusActive},
	})
	require.NoError(t, err)

	results, err := backend.QuerySnapshots(ctx, SnapshotFilter{
		NodeRoles: []string{NodeRoleProxySQL},
	})
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, NodeRoleProxySQL, results[0].NodeRole)
}

func TestDeleteSnapshotsBefore(t *testing.T) {
	backend := newTestBackend(t)
	ctx := context.Background()

	old := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	recent := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)

	err := backend.InsertSnapshots(ctx, []NodeSnapshot{
		{CapturedAt: old, ControllerID: "c", ClusterID: 1, ClusterName: "x", ClusterType: "t", DBVendor: "v", NodeID: "c:1", Hostname: "h1", Port: 1, NodeRole: NodeRoleDatabase, NodeStatus: NodeStatusActive},
		{CapturedAt: recent, ControllerID: "c", ClusterID: 1, ClusterName: "x", ClusterType: "t", DBVendor: "v", NodeID: "c:1", Hostname: "h1", Port: 1, NodeRole: NodeRoleDatabase, NodeStatus: NodeStatusActive},
	})
	require.NoError(t, err)

	cutoff := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	deleted, err := backend.DeleteSnapshotsBefore(ctx, cutoff)
	require.NoError(t, err)
	assert.Equal(t, int64(1), deleted)

	count, err := backend.CountSnapshots(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)
}

func TestOldestSnapshotTime(t *testing.T) {
	backend := newTestBackend(t)
	ctx := context.Background()

	// Empty DB returns nil.
	oldest, err := backend.OldestSnapshotTime(ctx)
	require.NoError(t, err)
	assert.Nil(t, oldest)

	ts := time.Date(2026, 3, 15, 10, 0, 0, 0, time.UTC)
	err = backend.InsertSnapshots(ctx, []NodeSnapshot{
		{CapturedAt: ts, ControllerID: "c", ClusterID: 1, ClusterName: "x", ClusterType: "t", DBVendor: "v", NodeID: "c:1", Hostname: "h1", Port: 1, NodeRole: NodeRoleDatabase, NodeStatus: NodeStatusActive},
	})
	require.NoError(t, err)

	oldest, err = backend.OldestSnapshotTime(ctx)
	require.NoError(t, err)
	require.NotNil(t, oldest)
	assert.Equal(t, ts, *oldest)
}

func TestInsertAndGetReport(t *testing.T) {
	backend := newTestBackend(t)
	ctx := context.Background()

	report := &BillingReport{
		ReportVersion: 1,
		PeriodStart:   time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
		PeriodEnd:     time.Date(2026, 4, 30, 23, 59, 59, 0, time.UTC),
		GeneratedAt:   time.Now().UTC().Truncate(time.Second),
		ReportData:    `{"total_billable_nodes":47}`,
		SHA256Hash:    "abc123hash",
		Signature:     "sig456",
		SigningKeyID:  "key-2026-01",
	}

	id, err := backend.InsertReport(ctx, report)
	require.NoError(t, err)
	assert.Greater(t, id, int64(0))

	// Get by ID.
	got, err := backend.GetReport(ctx, id)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, report.ReportVersion, got.ReportVersion)
	assert.Equal(t, report.ReportData, got.ReportData)
	assert.Equal(t, report.SHA256Hash, got.SHA256Hash)
	assert.Equal(t, report.Signature, got.Signature)
	assert.Equal(t, report.SigningKeyID, got.SigningKeyID)

	// Get by period.
	got2, err := backend.GetReportByPeriod(ctx, report.PeriodStart, report.PeriodEnd)
	require.NoError(t, err)
	require.NotNil(t, got2)
	assert.Equal(t, id, got2.ID)
}

func TestGetReportByPeriod_ReturnsLatestVersion(t *testing.T) {
	backend := newTestBackend(t)
	ctx := context.Background()

	start := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 4, 30, 23, 59, 59, 0, time.UTC)

	for v := 1; v <= 3; v++ {
		_, err := backend.InsertReport(ctx, &BillingReport{
			ReportVersion: v,
			PeriodStart:   start,
			PeriodEnd:     end,
			GeneratedAt:   time.Now().UTC().Truncate(time.Second),
			ReportData:    `{"version":` + string(rune('0'+v)) + `}`,
			SHA256Hash:    "hash",
		})
		require.NoError(t, err)
	}

	got, err := backend.GetReportByPeriod(ctx, start, end)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, 3, got.ReportVersion)
}

func TestGetLatestReportVersion(t *testing.T) {
	backend := newTestBackend(t)
	ctx := context.Background()

	start := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 4, 30, 23, 59, 59, 0, time.UTC)

	// No reports yet.
	version, err := backend.GetLatestReportVersion(ctx, start, end)
	require.NoError(t, err)
	assert.Equal(t, 0, version)

	// Insert v1.
	_, err = backend.InsertReport(ctx, &BillingReport{
		ReportVersion: 1,
		PeriodStart:   start,
		PeriodEnd:     end,
		GeneratedAt:   time.Now().UTC().Truncate(time.Second),
		ReportData:    `{}`,
		SHA256Hash:    "hash",
	})
	require.NoError(t, err)

	version, err = backend.GetLatestReportVersion(ctx, start, end)
	require.NoError(t, err)
	assert.Equal(t, 1, version)
}

func TestListReports(t *testing.T) {
	backend := newTestBackend(t)
	ctx := context.Background()

	// Insert two reports for different periods.
	_, err := backend.InsertReport(ctx, &BillingReport{
		ReportVersion: 1,
		PeriodStart:   time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
		PeriodEnd:     time.Date(2026, 3, 31, 23, 59, 59, 0, time.UTC),
		GeneratedAt:   time.Now().UTC().Truncate(time.Second),
		ReportData:    `{"month":"march"}`,
		SHA256Hash:    "hash1",
	})
	require.NoError(t, err)

	_, err = backend.InsertReport(ctx, &BillingReport{
		ReportVersion: 1,
		PeriodStart:   time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
		PeriodEnd:     time.Date(2026, 4, 30, 23, 59, 59, 0, time.UTC),
		GeneratedAt:   time.Now().UTC().Truncate(time.Second),
		ReportData:    `{"month":"april"}`,
		SHA256Hash:    "hash2",
	})
	require.NoError(t, err)

	reports, err := backend.ListReports(ctx)
	require.NoError(t, err)
	assert.Len(t, reports, 2)
	// Ordered by period_start DESC.
	assert.Equal(t, time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC), reports[0].PeriodStart)
	assert.Equal(t, time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), reports[1].PeriodStart)
}

func TestGetReport_NotFound(t *testing.T) {
	backend := newTestBackend(t)
	ctx := context.Background()

	got, err := backend.GetReport(ctx, 999)
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestConfig_SetAndGet(t *testing.T) {
	backend := newTestBackend(t)
	ctx := context.Background()

	// Set a value.
	err := backend.SetConfig(ctx, ConfigBillingPeriodMonths, "1")
	require.NoError(t, err)

	val, err := backend.GetConfig(ctx, ConfigBillingPeriodMonths)
	require.NoError(t, err)
	assert.Equal(t, "1", val)

	// Upsert.
	err = backend.SetConfig(ctx, ConfigBillingPeriodMonths, "3")
	require.NoError(t, err)

	val, err = backend.GetConfig(ctx, ConfigBillingPeriodMonths)
	require.NoError(t, err)
	assert.Equal(t, "3", val)
}

func TestDatabaseSize(t *testing.T) {
	backend := newTestBackend(t)
	ctx := context.Background()

	size, err := backend.DatabaseSize(ctx)
	require.NoError(t, err)
	assert.Greater(t, size, int64(0))
}

func TestInsertSnapshots_EmptySlice(t *testing.T) {
	backend := newTestBackend(t)
	ctx := context.Background()

	err := backend.InsertSnapshots(ctx, nil)
	require.NoError(t, err)

	err = backend.InsertSnapshots(ctx, []NodeSnapshot{})
	require.NoError(t, err)
}

func TestNewSQLiteBackend_Idempotent(t *testing.T) {
	// Opening the same DB twice should not fail or lose data.
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "metering.db")

	b1, err := NewSQLiteBackend(dbPath)
	require.NoError(t, err)

	ctx := context.Background()
	err = b1.SetConfig(ctx, "test_key", "test_value")
	require.NoError(t, err)
	b1.Close()

	b2, err := NewSQLiteBackend(dbPath)
	require.NoError(t, err)
	defer b2.Close()

	val, err := b2.GetConfig(ctx, "test_key")
	require.NoError(t, err)
	assert.Equal(t, "test_value", val)
}

func TestSQLiteBackend_DatabasePath(t *testing.T) {
	backend := newTestBackend(t)
	ctx := context.Background()

	// DB file should exist.
	_, err := os.Stat(backend.path)
	require.NoError(t, err)

	// Size should be nonzero after schema creation.
	size, err := backend.DatabaseSize(ctx)
	require.NoError(t, err)
	assert.Greater(t, size, int64(0))
}
