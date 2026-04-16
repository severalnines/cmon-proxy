package metering

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/severalnines/cmon-proxy/cmon/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockProvider implements ClusterDataProvider for testing.
type mockProvider struct {
	data map[string]*ControllerClusters
}

func (m *mockProvider) FetchAllClusters() map[string]*ControllerClusters {
	return m.data
}

func newTestCollectorSetup(t *testing.T) (*SQLiteBackend, *mockProvider) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "metering_test.db")
	backend, err := NewSQLiteBackend(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { backend.Close() })

	provider := &mockProvider{
		data: map[string]*ControllerClusters{
			"https://ctrl-1:9501": {
				ControllerID: "ctrl-1",
				Clusters: []*api.Cluster{
					{
						ClusterID:   1,
						ClusterName: "prod-galera",
						ClusterType: "galera",
						Vendor:      "Percona",
						Tags:        []string{"customer-123"},
						Hosts: []*api.Host{
							{
								WithClassName: &api.WithClassName{ClassName: "CmonGaleraHost"},
								IP:            "10.0.1.1",
								Hostname:      "db-node-1",
								Port:          3306,
								HostStatus:    "CmonHostOnline",
								Nodetype:      "galera",
							},
							{
								WithClassName: &api.WithClassName{ClassName: "CmonGaleraHost"},
								IP:            "10.0.1.2",
								Hostname:      "db-node-2",
								Port:          3306,
								HostStatus:    "CmonHostOnline",
								Nodetype:      "galera",
							},
							{
								WithClassName: &api.WithClassName{ClassName: "CmonProxySqlHost"},
								IP:            "10.0.1.3",
								Hostname:      "proxy-1",
								Port:          6033,
								HostStatus:    "CmonHostOnline",
								Nodetype:      "proxysql",
							},
							// Controller host — should be skipped.
							{
								WithClassName: &api.WithClassName{ClassName: "CmonHost"},
								IP:            "10.0.1.100",
								Hostname:      "controller",
								Port:          9500,
								HostStatus:    "CmonHostOnline",
								Nodetype:      "controller",
							},
							// Non-eligible host (e.g., HAProxy) — should be skipped.
							{
								WithClassName: &api.WithClassName{ClassName: "CmonHaProxyHost"},
								IP:            "10.0.1.4",
								Hostname:      "haproxy-1",
								Port:          3307,
								HostStatus:    "CmonHostOnline",
								Nodetype:      "haproxy",
							},
						},
					},
				},
			},
		},
	}

	return backend, provider
}

func TestCollector_Collect_BasicSnapshots(t *testing.T) {
	backend, provider := newTestCollectorSetup(t)

	collector := NewCollector(backend, provider, time.Hour)

	ctx := context.Background()
	collector.collect(ctx)

	// Should have 3 eligible nodes: 2 galera + 1 proxysql.
	count, err := backend.CountSnapshots(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(3), count)

	snapshots, err := backend.QuerySnapshots(ctx, SnapshotFilter{})
	require.NoError(t, err)
	assert.Len(t, snapshots, 3)

	// Verify first galera node.
	assert.Equal(t, "ctrl-1:10.0.1.1", snapshots[0].NodeID)
	assert.Equal(t, "ctrl-1", snapshots[0].ControllerID)
	assert.Equal(t, uint64(1), snapshots[0].ClusterID)
	assert.Equal(t, "prod-galera", snapshots[0].ClusterName)
	assert.Equal(t, "galera", snapshots[0].ClusterType)
	assert.Equal(t, "percona", snapshots[0].DBVendor)
	assert.Equal(t, NodeRoleDatabase, snapshots[0].NodeRole)
	assert.Equal(t, NodeStatusActive, snapshots[0].NodeStatus)
	assert.Equal(t, []string{"customer-123"}, snapshots[0].Tags)

	// Verify ProxySQL node.
	assert.Equal(t, "ctrl-1:10.0.1.3", snapshots[2].NodeID)
	assert.Equal(t, NodeRoleProxySQL, snapshots[2].NodeRole)
	assert.Equal(t, NodeStatusActive, snapshots[2].NodeStatus)
}

func TestCollector_Collect_StoppedNode(t *testing.T) {
	backend, provider := newTestCollectorSetup(t)

	// Mark one node as offline.
	provider.data["https://ctrl-1:9501"].Clusters[0].Hosts[0].HostStatus = "CmonHostShutDown"

	collector := NewCollector(backend, provider, time.Hour)

	ctx := context.Background()
	collector.collect(ctx)

	snapshots, err := backend.QuerySnapshots(ctx, SnapshotFilter{
		NodeStatuses: []string{NodeStatusStopped},
	})
	require.NoError(t, err)
	assert.Len(t, snapshots, 1)
	assert.Equal(t, "ctrl-1:10.0.1.1", snapshots[0].NodeID)
	assert.Equal(t, NodeStatusStopped, snapshots[0].NodeStatus)
}

func TestCollector_Collect_DetectsRemovedNodes(t *testing.T) {
	backend, provider := newTestCollectorSetup(t)

	collector := NewCollector(backend, provider, time.Hour)

	ctx := context.Background()

	// First collection: 3 nodes.
	collector.collect(ctx)
	count, _ := backend.CountSnapshots(ctx)
	assert.Equal(t, int64(3), count)

	// Remove one host from the cluster.
	provider.data["https://ctrl-1:9501"].Clusters[0].Hosts =
		provider.data["https://ctrl-1:9501"].Clusters[0].Hosts[1:] // remove first galera host

	// Second collection: 2 active + 1 removed.
	collector.collect(ctx)
	count, _ = backend.CountSnapshots(ctx)
	assert.Equal(t, int64(6), count) // 3 from first + 3 from second

	// Check that the removed node was recorded.
	removed, err := backend.QuerySnapshots(ctx, SnapshotFilter{
		NodeStatuses: []string{NodeStatusRemoved},
	})
	require.NoError(t, err)
	assert.Len(t, removed, 1)
	assert.Equal(t, "ctrl-1:10.0.1.1", removed[0].NodeID)
	assert.Equal(t, NodeStatusRemoved, removed[0].NodeStatus)
}

func TestCollector_Collect_ControllerUnreachable(t *testing.T) {
	backend, provider := newTestCollectorSetup(t)

	collector := NewCollector(backend, provider, time.Hour)

	ctx := context.Background()

	// First collection: 3 nodes.
	collector.collect(ctx)
	count, _ := backend.CountSnapshots(ctx)
	assert.Equal(t, int64(3), count)

	// Controller becomes unreachable.
	provider.data["https://ctrl-1:9501"].Err = assert.AnError
	provider.data["https://ctrl-1:9501"].Clusters = nil

	// Second collection: controller error — nodes should NOT be marked removed.
	collector.collect(ctx)
	count, _ = backend.CountSnapshots(ctx)
	// No new snapshots inserted (controller errored), but no "removed" rows either.
	assert.Equal(t, int64(3), count)
}

func TestCollector_Collect_MultipleControllers(t *testing.T) {
	backend, provider := newTestCollectorSetup(t)

	// Add a second controller.
	provider.data["https://ctrl-2:9501"] = &ControllerClusters{
		ControllerID: "ctrl-2",
		Clusters: []*api.Cluster{
			{
				ClusterID:   1,
				ClusterName: "staging-pg",
				ClusterType: "postgresql",
				Vendor:      "PostgreSQL",
				Hosts: []*api.Host{
					{
						WithClassName: &api.WithClassName{ClassName: "CmonPostgreSqlHost"},
						IP:            "10.0.2.1",
						Hostname:      "pg-primary",
						Port:          5432,
						HostStatus:    "CmonHostOnline",
						Nodetype:      "postgresql",
					},
				},
			},
		},
	}

	collector := NewCollector(backend, provider, time.Hour)

	ctx := context.Background()
	collector.collect(ctx)

	count, _ := backend.CountSnapshots(ctx)
	assert.Equal(t, int64(4), count) // 3 from ctrl-1 + 1 from ctrl-2

	// Verify ctrl-2 node.
	nodeID := "ctrl-2"
	snapshots, err := backend.QuerySnapshots(ctx, SnapshotFilter{
		ControllerID: &nodeID,
	})
	require.NoError(t, err)
	assert.Len(t, snapshots, 1)
	assert.Equal(t, "ctrl-2:10.0.2.1", snapshots[0].NodeID)
	assert.Equal(t, "postgresql", snapshots[0].ClusterType)
	assert.Equal(t, "postgresql", snapshots[0].DBVendor)
}

func TestCollector_Collect_RecordsLastSuccessfulCollection(t *testing.T) {
	backend, provider := newTestCollectorSetup(t)

	collector := NewCollector(backend, provider, time.Hour)

	ctx := context.Background()
	collector.collect(ctx)

	val, err := backend.GetConfig(ctx, ConfigLastSuccessfulCollection)
	require.NoError(t, err)
	assert.NotEmpty(t, val)

	// Should parse as a valid timestamp.
	_, err = time.Parse(time.RFC3339, val)
	require.NoError(t, err)
}

func TestCollector_Collect_EmptyProvider(t *testing.T) {
	backend, _ := newTestCollectorSetup(t)

	emptyProvider := &mockProvider{data: map[string]*ControllerClusters{}}
	collector := NewCollector(backend, emptyProvider, time.Hour)

	ctx := context.Background()
	collector.collect(ctx)

	count, _ := backend.CountSnapshots(ctx)
	assert.Equal(t, int64(0), count)
}

func TestCollector_StartAndStop(t *testing.T) {
	backend, provider := newTestCollectorSetup(t)

	// Use a very short interval for test.
	collector := NewCollector(backend, provider, 50*time.Millisecond)

	collector.Start()

	// Let it run a couple of cycles.
	time.Sleep(200 * time.Millisecond)

	collector.Stop()

	ctx := context.Background()
	count, _ := backend.CountSnapshots(ctx)
	// Should have collected at least once (catch-up on startup).
	assert.Greater(t, count, int64(0))
}

func TestNodeStatusFromHostStatus(t *testing.T) {
	tests := []struct {
		hostStatus string
		expected   string
	}{
		{"CmonHostOnline", NodeStatusActive},
		{"CmonHostRecovery", NodeStatusActive},
		{"CmonHostShutDown", NodeStatusStopped},
		{"CmonHostOffline", NodeStatusStopped},
		{"CmonHostUnknown", NodeStatusActive}, // unknown defaults to active
	}

	for _, tt := range tests {
		t.Run(tt.hostStatus, func(t *testing.T) {
			assert.Equal(t, tt.expected, nodeStatusFromHostStatus(tt.hostStatus))
		})
	}
}

func TestExtractControllerID(t *testing.T) {
	tests := []struct {
		nodeID   string
		expected string
	}{
		{"ctrl-1:10.0.1.1", "ctrl-1"},
		{"https://ctrl-1:9501:10.0.1.1", "https://ctrl-1:9501"},
		{"simple", "simple"},
	}

	for _, tt := range tests {
		t.Run(tt.nodeID, func(t *testing.T) {
			assert.Equal(t, tt.expected, extractControllerID(tt.nodeID))
		})
	}
}
