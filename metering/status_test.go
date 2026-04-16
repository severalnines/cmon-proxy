package metering

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newStatusTestBackend(t *testing.T) *SQLiteBackend {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "status_test.db")
	backend, err := NewSQLiteBackend(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { backend.Close() })
	return backend
}

func TestGetStatus_Healthy(t *testing.T) {
	backend := newStatusTestBackend(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	require.NoError(t, backend.SetConfig(ctx, ConfigLastSuccessfulCollection, now.Format(time.RFC3339)))
	require.NoError(t, backend.SetConfig(ctx, ConfigRetentionMonths, "6"))
	require.NoError(t, backend.SetConfig(ctx, ConfigLastRetentionCleanup, now.Format(time.RFC3339)))
	require.NoError(t, backend.SetConfig(ctx, ConfigLastCleanupDeletedRows, "12"))

	require.NoError(t, backend.InsertSnapshots(ctx, []NodeSnapshot{{
		CapturedAt:   now,
		ControllerID: "ctrl-1",
		ClusterID:    1,
		ClusterName:  "prod",
		ClusterType:  "galera",
		DBVendor:     "percona",
		NodeID:       "ctrl-1:10.0.1.1",
		Hostname:     "db1",
		Port:         3306,
		NodeRole:     NodeRoleDatabase,
		NodeStatus:   NodeStatusActive,
	}}))

	status, err := GetStatus(ctx, backend, true, time.Hour)
	require.NoError(t, err)

	assert.True(t, status.CollectionHealthy)
	assert.Equal(t, "ok", status.HealthStatus)
	assert.Equal(t, int64(1), status.TotalSnapshots)
	assert.Equal(t, 6, status.RetentionMonths)
	assert.Equal(t, int64(12), status.LastCleanupDeleted)
	assert.Empty(t, status.LastCollectionError)
	assert.Empty(t, status.LastCleanupError)
}

func TestGetStatus_WarningWhenCollectionIsStaleOrErrored(t *testing.T) {
	backend := newStatusTestBackend(t)
	ctx := context.Background()
	stale := time.Now().UTC().Add(-3 * time.Hour).Truncate(time.Second)

	require.NoError(t, backend.SetConfig(ctx, ConfigLastSuccessfulCollection, stale.Format(time.RFC3339)))
	require.NoError(t, backend.SetConfig(ctx, ConfigLastCollectionError, "1 controller returned errors"))
	require.NoError(t, backend.SetConfig(ctx, ConfigLastCleanupError, "database locked"))

	status, err := GetStatus(ctx, backend, true, time.Hour)
	require.NoError(t, err)

	assert.False(t, status.CollectionHealthy)
	assert.Equal(t, "warning", status.HealthStatus)
	assert.Equal(t, "1 controller returned errors", status.LastCollectionError)
	assert.Equal(t, "database locked", status.LastCleanupError)
	assert.Equal(t, DefaultRetentionMonths, status.RetentionMonths)
}
