package metering_test

// Integration tests that run against a real CMON controller.
// Skipped unless CMON_ENDPOINT is set in the environment.
//
// To run:
//   source .env && go test -v -run TestIntegration ./metering/...

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/severalnines/cmon-proxy/cmon"
	"github.com/severalnines/cmon-proxy/cmon/api"
	"github.com/severalnines/cmon-proxy/config"
	"github.com/severalnines/cmon-proxy/metering"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func skipIfNoCmon(t *testing.T) {
	t.Helper()
	if os.Getenv("CMON_ENDPOINT") == "" {
		t.Skip("CMON_ENDPOINT not set — skipping live integration test")
	}
}

func cmonClient(t *testing.T) *cmon.Client {
	t.Helper()
	client := cmon.NewClient(&config.CmonInstance{
		Url:      os.Getenv("CMON_ENDPOINT"),
		Username: os.Getenv("CMON_USERNAME"),
		Password: os.Getenv("CMON_PASSWORD"),
	}, 30)

	err := client.Authenticate()
	require.NoError(t, err, "Failed to authenticate with CMON controller at %s", os.Getenv("CMON_ENDPOINT"))
	return client
}

func newIntegrationBackend(t *testing.T) *metering.SQLiteBackend {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "integration_test.db")
	backend, err := metering.NewSQLiteBackend(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { backend.Close() })
	return backend
}

// liveProvider implements ClusterDataProvider using a real CMON client.
type liveProvider struct {
	client *cmon.Client
	url    string
}

func (p *liveProvider) FetchAllClusters() map[string]*metering.ControllerClusters {
	resp, err := p.client.GetAllClusterInfo(&api.GetAllClusterInfoRequest{
		WithOperation: &api.WithOperation{Operation: "getAllClusterInfo"},
		WithHosts:     true,
		WithTags:      true,
	})

	result := map[string]*metering.ControllerClusters{
		p.url: {
			ControllerID: p.url,
		},
	}

	if err != nil {
		result[p.url].Err = err
		return result
	}

	result[p.url].Clusters = resp.Clusters
	return result
}

// ---------------------------------------------------------------------------
// Test: Authenticate and fetch cluster info
// ---------------------------------------------------------------------------

func TestIntegration_CmonAuthenticate(t *testing.T) {
	skipIfNoCmon(t)
	client := cmonClient(t)

	resp, err := client.GetAllClusterInfo(&api.GetAllClusterInfoRequest{
		WithOperation: &api.WithOperation{Operation: "getAllClusterInfo"},
		WithHosts:     true,
		WithTags:      true,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	t.Logf("Controller returned %d clusters", len(resp.Clusters))
	for _, cluster := range resp.Clusters {
		t.Logf("  Cluster %d: %s (type=%s, vendor=%s, hosts=%d, tags=%v)",
			cluster.ClusterID, cluster.ClusterName, cluster.ClusterType,
			cluster.Vendor, len(cluster.Hosts), cluster.Tags)
		for _, host := range cluster.Hosts {
			className := ""
			if host.WithClassName != nil {
				className = host.ClassName
			}
			t.Logf("    Host: %s:%d class=%s nodetype=%s status=%s ip=%s",
				host.Hostname, host.Port, className, host.Nodetype, host.HostStatus, host.IP)
		}
	}

	assert.Greater(t, len(resp.Clusters), 0, "Expected at least one cluster from the controller")
}

// ---------------------------------------------------------------------------
// Test: Eligible node classification against live data
// ---------------------------------------------------------------------------

func TestIntegration_EligibleNodeClassification(t *testing.T) {
	skipIfNoCmon(t)
	client := cmonClient(t)

	resp, err := client.GetAllClusterInfo(&api.GetAllClusterInfoRequest{
		WithOperation: &api.WithOperation{Operation: "getAllClusterInfo"},
		WithHosts:     true,
	})
	require.NoError(t, err)

	var eligible, ineligible int
	for _, cluster := range resp.Clusters {
		for _, host := range cluster.Hosts {
			if host.Nodetype == "controller" {
				continue
			}
			className := ""
			if host.WithClassName != nil {
				className = host.ClassName
			}
			if metering.IsEligibleNode(className) {
				eligible++
				t.Logf("  ELIGIBLE: %s:%d class=%s → role=%s",
					host.IP, host.Port, className, metering.NodeRoleFromClassName(className))
			} else {
				ineligible++
				t.Logf("  INELIGIBLE: %s:%d class=%s nodetype=%s",
					host.IP, host.Port, className, host.Nodetype)
			}
		}
	}

	t.Logf("Eligible: %d, Ineligible: %d", eligible, ineligible)
	assert.Greater(t, eligible, 0, "Expected at least one eligible node")
}

// ---------------------------------------------------------------------------
// Test: Full collection pipeline against live controller
// ---------------------------------------------------------------------------

func TestIntegration_CollectSnapshots(t *testing.T) {
	skipIfNoCmon(t)
	client := cmonClient(t)
	backend := newIntegrationBackend(t)
	ctx := context.Background()

	provider := &liveProvider{
		client: client,
		url:    os.Getenv("CMON_ENDPOINT"),
	}

	collector := metering.NewCollector(backend, provider, time.Hour)

	// Run a single collection (don't start the ticker).
	collector.CollectOnce(ctx)

	count, err := backend.CountSnapshots(ctx)
	require.NoError(t, err)

	t.Logf("Collected %d snapshots", count)
	assert.Greater(t, count, int64(0), "Expected at least one snapshot from live controller")

	// Verify snapshot content.
	snapshots, err := backend.QuerySnapshots(ctx, metering.SnapshotFilter{})
	require.NoError(t, err)

	for _, s := range snapshots {
		t.Logf("  Snapshot: node=%s cluster=%s(%d) type=%s vendor=%s role=%s status=%s vcpu=%v ram=%v vol=%v tags=%v",
			s.NodeID, s.ClusterName, s.ClusterID, s.ClusterType, s.DBVendor,
			s.NodeRole, s.NodeStatus, s.VCPU, s.RAMMB, s.VolumeGB, s.Tags)

		assert.NotEmpty(t, s.NodeID)
		assert.NotEmpty(t, s.ControllerID)
		assert.NotEmpty(t, s.ClusterName)
		assert.NotEmpty(t, s.ClusterType)
		assert.NotEmpty(t, s.NodeRole)
		assert.Contains(t, []string{metering.NodeStatusActive, metering.NodeStatusStopped}, s.NodeStatus)
	}

	// Verify last_successful_collection was recorded.
	lastCol, err := backend.GetConfig(ctx, metering.ConfigLastSuccessfulCollection)
	require.NoError(t, err)
	assert.NotEmpty(t, lastCol)
}

// ---------------------------------------------------------------------------
// Test: Full pipeline — collect → generate report → seal → verify
// ---------------------------------------------------------------------------

func TestIntegration_FullPipeline(t *testing.T) {
	skipIfNoCmon(t)
	client := cmonClient(t)
	backend := newIntegrationBackend(t)
	ctx := context.Background()

	provider := &liveProvider{
		client: client,
		url:    os.Getenv("CMON_ENDPOINT"),
	}

	// Collect snapshots (simulate multiple hourly ticks by collecting several times
	// with different timestamps — we re-use the same data but the collector records it).
	collector := metering.NewCollector(backend, provider, time.Hour)
	for i := 0; i < 30; i++ {
		collector.CollectOnce(ctx)
	}

	count, err := backend.CountSnapshots(ctx)
	require.NoError(t, err)
	t.Logf("Total snapshots after 30 collections: %d", count)

	// Generate report for a wide period that includes all snapshots.
	now := time.Now().UTC()
	periodStart := now.Add(-24 * time.Hour)
	periodEnd := now.Add(time.Hour)

	// Use minActiveHours=1 since we may only have a handful of snapshot hours.
	gen := metering.NewReportGenerator(backend, 1)
	reportData, err := gen.Generate(ctx, periodStart, periodEnd, 1)
	require.NoError(t, err)
	require.NotNil(t, reportData)

	t.Logf("Report: %d billable nodes, %d type/vendor groups",
		reportData.Summary.TotalBillableNodes, len(reportData.ByTypeAndVendor))
	assert.Greater(t, reportData.Summary.TotalBillableNodes, 0, "Expected at least one billable node")

	for _, tv := range reportData.ByTypeAndVendor {
		t.Logf("  %s/%s: max_concurrent=%d max_vcpu=%d max_ram_gb=%d max_vol_gb=%d",
			tv.ClusterType, tv.DBVendor, tv.MaxConcurrentNodes, tv.MaxVCPU, tv.MaxRAMGB, tv.MaxVolumeGB)
	}
	for _, nd := range reportData.NodeDetails {
		t.Logf("  Node %s: hours=%d vcpu=%d ram=%dMB vol=%dGB changes=%d",
			nd.NodeID, nd.ActiveHours, nd.MaxVCPU, nd.MaxRAMMB, nd.MaxVolumeGB, len(nd.ResourceChanges))
	}

	// Seal the report.
	signingKey := []byte("integration-test-key")
	sealed, err := metering.SealReport(reportData, signingKey, "test-key-1")
	require.NoError(t, err)

	t.Logf("Sealed: hash=%s sig=%s", sealed.SHA256Hash[:16]+"...", sealed.Signature[:16]+"...")

	// Store the sealed report.
	billingReport := &metering.BillingReport{
		ReportVersion: 1,
		PeriodStart:   periodStart,
		PeriodEnd:     periodEnd,
		GeneratedAt:   time.Now().UTC(),
		ReportData:    sealed.CanonicalJSON,
		SHA256Hash:    sealed.SHA256Hash,
		Signature:     sealed.Signature,
		SigningKeyID:  sealed.SigningKeyID,
	}
	reportID, err := backend.InsertReport(ctx, billingReport)
	require.NoError(t, err)
	t.Logf("Stored report with ID=%d", reportID)

	// Retrieve and verify.
	stored, err := backend.GetReport(ctx, reportID)
	require.NoError(t, err)
	require.NotNil(t, stored)

	hashOK, sigOK := metering.VerifySeal(stored.ReportData, stored.SHA256Hash, stored.Signature, signingKey)
	assert.True(t, hashOK, "Hash verification failed")
	assert.True(t, sigOK, "Signature verification failed")
	t.Logf("Verification: hash_valid=%v signature_valid=%v", hashOK, sigOK)

	// Tamper test: modify one byte and verify it fails.
	tampered := stored.ReportData[:10] + "X" + stored.ReportData[11:]
	hashOK2, sigOK2 := metering.VerifySeal(tampered, stored.SHA256Hash, stored.Signature, signingKey)
	assert.False(t, hashOK2, "Tampered hash should fail")
	assert.False(t, sigOK2, "Tampered signature should fail")
	t.Log("Tamper detection: confirmed")

	// Verify report JSON parses back correctly.
	var parsed metering.ReportData
	err = json.Unmarshal([]byte(stored.ReportData), &parsed)
	require.NoError(t, err)
	assert.Equal(t, reportData.Summary.TotalBillableNodes, parsed.Summary.TotalBillableNodes)
}

// ---------------------------------------------------------------------------
// Test: Vendor normalization on live data
// ---------------------------------------------------------------------------

func TestIntegration_VendorNormalization(t *testing.T) {
	skipIfNoCmon(t)
	client := cmonClient(t)

	resp, err := client.GetAllClusterInfo(&api.GetAllClusterInfoRequest{
		WithOperation: &api.WithOperation{Operation: "getAllClusterInfo"},
		WithHosts:     true,
	})
	require.NoError(t, err)

	for _, cluster := range resp.Clusters {
		normalized := metering.NormalizeVendor(cluster.Vendor)
		t.Logf("Cluster %q: raw vendor=%q → normalized=%q", cluster.ClusterName, cluster.Vendor, normalized)
		assert.NotEmpty(t, normalized, "Vendor should never normalize to empty string")
	}
}
