package metering_test

// Long-running soak test that collects metering data for 2 hours against
// a real CMON controller, then generates and saves a billing report to disk.
//
// Skipped unless both CMON_ENDPOINT and METERING_SOAK_TEST are set.
//
// To run:
//   source .env
//   export METERING_SOAK_TEST=true
//   go test -v -run TestSoak_TwoHourMeteringCycle ./metering/... -timeout 150m
//
// Reports are saved to ./metering-soak-output/ in the current working directory.

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/severalnines/cmon-proxy/cmon"
	"github.com/severalnines/cmon-proxy/cmon/api"
	"github.com/severalnines/cmon-proxy/config"
	"github.com/severalnines/cmon-proxy/metering"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

const (
	soakCollectionInterval = 10 * time.Minute
	soakDuration           = 2 * time.Hour
	soakOutputDir          = "metering-soak-output"
)

func TestSoak_TwoHourMeteringCycle(t *testing.T) {
	if os.Getenv("CMON_ENDPOINT") == "" {
		t.Skip("CMON_ENDPOINT not set — skipping soak test")
	}
	if os.Getenv("METERING_SOAK_TEST") == "" {
		t.Skip("METERING_SOAK_TEST not set — skipping soak test (set to 'true' to enable)")
	}

	// Initialize logger for stat collection debug output.
	logger, _ := zap.NewDevelopment()
	zap.ReplaceGlobals(logger)

	t.Logf("=== SOAK TEST STARTING ===")
	t.Logf("Controller:  %s", os.Getenv("CMON_ENDPOINT"))
	t.Logf("Interval:    %s", soakCollectionInterval)
	t.Logf("Duration:    %s", soakDuration)
	t.Logf("Expected collections: %d", int(soakDuration/soakCollectionInterval))
	t.Logf("")

	// Create CMON client.
	client := cmon.NewClient(&config.CmonInstance{
		Url:      os.Getenv("CMON_ENDPOINT"),
		Username: os.Getenv("CMON_USERNAME"),
		Password: os.Getenv("CMON_PASSWORD"),
	}, 30)

	err := client.Authenticate()
	require.NoError(t, err, "Failed to authenticate with CMON controller")
	t.Logf("Authenticated with CMON controller")

	// Create storage.
	dbPath := filepath.Join(t.TempDir(), "soak_test.db")
	backend, err := metering.NewSQLiteBackend(dbPath)
	require.NoError(t, err)
	defer backend.Close()

	// Create provider with stat collection.
	provider := &soakProvider{
		client: client,
		url:    os.Getenv("CMON_ENDPOINT"),
	}

	// Record test start time (used as billing period start).
	periodStart := time.Now().UTC().Truncate(time.Minute)

	// Create and start collector.
	collector := metering.NewCollector(backend, provider, soakCollectionInterval)
	collector.Start()
	t.Logf("Collector started at %s", periodStart.Format(time.RFC3339))

	// Wait for the soak duration, logging progress periodically.
	ctx := context.Background()
	statusTicker := time.NewTicker(5 * time.Minute)
	defer statusTicker.Stop()

	deadline := time.After(soakDuration)
	collectionCount := 0

	t.Logf("Waiting %s for data collection...", soakDuration)
	t.Logf("")

waitLoop:
	for {
		select {
		case <-deadline:
			break waitLoop
		case <-statusTicker.C:
			elapsed := time.Since(periodStart).Truncate(time.Second)
			count, _ := backend.CountSnapshots(ctx)
			lastCol, _ := backend.GetConfig(ctx, metering.ConfigLastSuccessfulCollection)
			dbSize, _ := backend.DatabaseSize(ctx)

			// Estimate collection count from snapshot count and initial cluster count.
			if count > 0 && collectionCount == 0 {
				// Get initial node count from first collection.
				resp, err := client.GetAllClusterInfo(&api.GetAllClusterInfoRequest{
					WithOperation: &api.WithOperation{Operation: "getAllClusterInfo"},
					WithHosts:     true,
				})
				if err == nil {
					nodeCount := 0
					for _, c := range resp.Clusters {
						for _, h := range c.Hosts {
							if h.Nodetype != "controller" {
								className := ""
								if h.WithClassName != nil {
									className = h.ClassName
								}
								if metering.IsEligibleNode(className) {
									nodeCount++
								}
							}
						}
					}
					if nodeCount > 0 {
						collectionCount = int(count) / nodeCount
					}
				}
			}

			t.Logf("[%s elapsed] snapshots=%d collections=~%d last_collection=%s db_size=%d bytes",
				elapsed, count, collectionCount, lastCol, dbSize)
		}
	}

	// Stop the collector.
	collector.Stop()
	periodEnd := time.Now().UTC().Truncate(time.Minute)
	t.Logf("")
	t.Logf("Collector stopped at %s", periodEnd.Format(time.RFC3339))

	// Final snapshot stats.
	totalSnapshots, _ := backend.CountSnapshots(ctx)
	dbSize, _ := backend.DatabaseSize(ctx)
	t.Logf("Total snapshots collected: %d", totalSnapshots)
	t.Logf("Database size: %d bytes", dbSize)
	t.Logf("")

	require.Greater(t, totalSnapshots, int64(0), "No snapshots were collected during the soak period")

	// Generate billing report.
	t.Logf("=== GENERATING BILLING REPORT ===")
	t.Logf("Period: %s to %s", periodStart.Format(time.RFC3339), periodEnd.Format(time.RFC3339))

	// Use minActiveHours=1 since we're only running for 2 hours.
	gen := metering.NewReportGenerator(backend, 1)
	reportData, err := gen.Generate(ctx, periodStart, periodEnd, 1)
	require.NoError(t, err)
	require.NotNil(t, reportData)

	t.Logf("Billable nodes: %d", reportData.Summary.TotalBillableNodes)
	t.Logf("Type/vendor groups: %d", len(reportData.ByTypeAndVendor))
	t.Logf("")

	assert.Greater(t, reportData.Summary.TotalBillableNodes, 0, "Expected at least one billable node")

	for _, tv := range reportData.ByTypeAndVendor {
		t.Logf("  %s / %s: concurrent=%d vcpu=%d ram_gb=%d vol_gb=%d",
			tv.ClusterType, tv.DBVendor, tv.MaxConcurrentNodes,
			tv.MaxVCPU, tv.MaxRAMGB, tv.MaxVolumeGB)
	}
	t.Logf("")

	for _, nd := range reportData.NodeDetails {
		t.Logf("  %-45s hours=%-3d vcpu=%-3d ram=%-6dMB vol=%-5dGB changes=%d",
			nd.NodeID, nd.ActiveHours, nd.MaxVCPU, nd.MaxRAMMB, nd.MaxVolumeGB, len(nd.ResourceChanges))
	}
	t.Logf("")

	// Seal the report.
	signingKey := []byte("soak-test-signing-key")
	sealed, err := metering.SealReport(reportData, signingKey, "soak-test-key")
	require.NoError(t, err)

	t.Logf("Report sealed: hash=%s", sealed.SHA256Hash)

	// Store in DB.
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

	// Verify the seal.
	stored, err := backend.GetReport(ctx, reportID)
	require.NoError(t, err)
	hashOK, sigOK := metering.VerifySeal(stored.ReportData, stored.SHA256Hash, stored.Signature, signingKey)
	assert.True(t, hashOK, "Hash verification failed")
	assert.True(t, sigOK, "Signature verification failed")
	t.Logf("Seal verified: hash_valid=%v signature_valid=%v", hashOK, sigOK)
	t.Logf("")

	// Save outputs to disk.
	t.Logf("=== SAVING REPORTS TO DISK ===")

	outputDir := soakOutputDir
	err = os.MkdirAll(outputDir, 0755)
	require.NoError(t, err)

	timestamp := periodStart.Format("2006-01-02T150405Z")

	// Save report JSON (pretty-printed).
	jsonPath := filepath.Join(outputDir, fmt.Sprintf("metering-report-%s.json", timestamp))
	prettyJSON, err := json.MarshalIndent(reportData, "", "  ")
	require.NoError(t, err)
	err = os.WriteFile(jsonPath, prettyJSON, 0644)
	require.NoError(t, err)
	t.Logf("Report JSON:    %s", jsonPath)

	// Save sealed report (canonical, with hash+sig metadata).
	sealedPath := filepath.Join(outputDir, fmt.Sprintf("metering-report-%s.sealed.json", timestamp))
	sealedMeta := map[string]any{
		"report_id":      reportID,
		"report_version": 1,
		"period_start":   periodStart.Format(time.RFC3339),
		"period_end":     periodEnd.Format(time.RFC3339),
		"generated_at":   billingReport.GeneratedAt.Format(time.RFC3339),
		"sha256_hash":    sealed.SHA256Hash,
		"signature":      sealed.Signature,
		"signing_key_id": sealed.SigningKeyID,
		"report_data":    json.RawMessage(sealed.CanonicalJSON),
	}
	sealedJSON, err := json.MarshalIndent(sealedMeta, "", "  ")
	require.NoError(t, err)
	err = os.WriteFile(sealedPath, sealedJSON, 0644)
	require.NoError(t, err)
	t.Logf("Sealed report:  %s", sealedPath)

	// Save CSV ZIP.
	csvPath := filepath.Join(outputDir, fmt.Sprintf("metering-report-%s.csv.zip", timestamp))
	csvZip, err := generateSoakCSVZip(reportData)
	require.NoError(t, err)
	err = os.WriteFile(csvPath, csvZip, 0644)
	require.NoError(t, err)
	t.Logf("CSV export:     %s", csvPath)

	// Save raw snapshots as CSV for audit.
	snapshotsPath := filepath.Join(outputDir, fmt.Sprintf("metering-snapshots-%s.csv", timestamp))
	snapshots, err := backend.QuerySnapshots(ctx, metering.SnapshotFilter{
		PeriodStart: &periodStart,
		PeriodEnd:   &periodEnd,
	})
	require.NoError(t, err)
	err = saveSnapshotsCSV(snapshotsPath, snapshots)
	require.NoError(t, err)
	t.Logf("Raw snapshots:  %s (%d rows)", snapshotsPath, len(snapshots))

	t.Logf("")
	t.Logf("=== SOAK TEST COMPLETE ===")
	t.Logf("Duration: %s", time.Since(periodStart).Truncate(time.Second))
	t.Logf("Output directory: %s", outputDir)
}

// soakProvider wraps a cmon.Client for the soak test, including stat collection.
type soakProvider struct {
	client *cmon.Client
	url    string
}

func (p *soakProvider) FetchAllClusters() map[string]*metering.ControllerClusters {
	log := zap.L().Sugar()

	resp, err := p.client.GetAllClusterInfo(&api.GetAllClusterInfoRequest{
		WithOperation: &api.WithOperation{Operation: "getAllClusterInfo"},
		WithHosts:     true,
		WithTags:      true,
	})

	result := map[string]*metering.ControllerClusters{
		p.url: {ControllerID: p.url},
	}

	if err != nil {
		result[p.url].Err = err
		return result
	}

	result[p.url].Clusters = resp.Clusters

	// Fetch hardware stats.
	hostStats := make(map[uint64]*metering.HostHardwareStats)
	now := time.Now().UTC()
	startTime := now.Add(-15 * time.Minute)

	clusterIDs := make(map[uint64]bool)
	for _, c := range resp.Clusters {
		clusterIDs[c.ClusterID] = true
	}

	for cid := range clusterIDs {
		memResp, err := p.client.GetStatByName(&api.GetStatByNameRequest{
			WithOperation: &api.WithOperation{Operation: "statByName"},
			WithClusterID: &api.WithClusterID{ClusterID: cid},
			Name:          api.StatTypeMemoryStat,
			WithHosts:     true,
			StartDateTime: api.StatTS(startTime),
			EndDateTime:   api.StatTS(now),
		})
		if err != nil {
			log.Debugf("memorystat error for cluster %d: %v", cid, err)
		} else {
			var entries []struct {
				HostID   uint64 `json:"hostid"`
				RAMTotal int64  `json:"ramtotal"`
			}
			json.Unmarshal(memResp.Data, &entries)
			for _, e := range entries {
				if e.RAMTotal > 0 {
					ramMB := int(e.RAMTotal / (1024 * 1024))
					if hw, ok := hostStats[e.HostID]; ok {
						hw.RAMMB = &ramMB
					} else {
						hostStats[e.HostID] = &metering.HostHardwareStats{RAMMB: &ramMB}
					}
				}
			}
		}

		diskResp, err := p.client.GetStatByName(&api.GetStatByNameRequest{
			WithOperation: &api.WithOperation{Operation: "statByName"},
			WithClusterID: &api.WithClusterID{ClusterID: cid},
			Name:          api.StatTypeDiskStat,
			WithHosts:     true,
			StartDateTime: api.StatTS(startTime),
			EndDateTime:   api.StatTS(now),
		})
		if err != nil {
			log.Debugf("diskstat error for cluster %d: %v", cid, err)
		} else {
			var entries []struct {
				HostID uint64 `json:"hostid"`
				Total  int64  `json:"total"`
			}
			json.Unmarshal(diskResp.Data, &entries)
			maxDisk := make(map[uint64]int64)
			for _, e := range entries {
				if e.Total > maxDisk[e.HostID] {
					maxDisk[e.HostID] = e.Total
				}
			}
			for hostID, total := range maxDisk {
				volGB := int(total / (1024 * 1024 * 1024))
				if hw, ok := hostStats[hostID]; ok {
					hw.VolumeGB = &volGB
				} else {
					hostStats[hostID] = &metering.HostHardwareStats{VolumeGB: &volGB}
				}
			}
		}
	}

	result[p.url].HostStats = hostStats
	return result
}

func generateSoakCSVZip(report *metering.ReportData) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	summaryFile, err := zw.Create("summary.csv")
	if err != nil {
		return nil, err
	}
	sw := csv.NewWriter(summaryFile)
	sw.Write([]string{"cluster_type", "db_vendor", "max_concurrent_nodes", "max_vcpu", "max_ram_gb", "max_volume_gb"})
	for _, tv := range report.ByTypeAndVendor {
		sw.Write([]string{
			tv.ClusterType, tv.DBVendor,
			strconv.Itoa(tv.MaxConcurrentNodes), strconv.Itoa(tv.MaxVCPU),
			strconv.Itoa(tv.MaxRAMGB), strconv.Itoa(tv.MaxVolumeGB),
		})
	}
	sw.Flush()

	detailsFile, err := zw.Create("node_details.csv")
	if err != nil {
		return nil, err
	}
	dw := csv.NewWriter(detailsFile)
	dw.Write([]string{
		"node_id", "controller_id", "cluster_id", "cluster_name", "cluster_type",
		"db_vendor", "node_role", "active_hours",
		"max_vcpu", "max_vcpu_observed_at",
		"max_ram_mb", "max_ram_observed_at",
		"max_volume_gb", "max_volume_observed_at",
	})
	for _, nd := range report.NodeDetails {
		dw.Write([]string{
			nd.NodeID, nd.ControllerID, strconv.FormatUint(nd.ClusterID, 10),
			nd.ClusterName, nd.ClusterType, nd.DBVendor, nd.NodeRole,
			strconv.Itoa(nd.ActiveHours), strconv.Itoa(nd.MaxVCPU), nd.MaxVCPUObservedAt,
			strconv.Itoa(nd.MaxRAMMB), nd.MaxRAMObservedAt,
			strconv.Itoa(nd.MaxVolumeGB), nd.MaxVolumeObservedAt,
		})
	}
	dw.Flush()

	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func saveSnapshotsCSV(path string, snapshots []metering.NodeSnapshot) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	w.Write([]string{
		"captured_at", "controller_id", "cluster_id", "cluster_name", "cluster_type",
		"db_vendor", "node_id", "hostname", "port", "node_role", "node_status",
		"vcpu", "ram_mb", "volume_gb", "tags",
	})

	for _, s := range snapshots {
		vcpu, ram, vol := "", "", ""
		if s.VCPU != nil {
			vcpu = strconv.Itoa(*s.VCPU)
		}
		if s.RAMMB != nil {
			ram = strconv.Itoa(*s.RAMMB)
		}
		if s.VolumeGB != nil {
			vol = strconv.Itoa(*s.VolumeGB)
		}
		tagsJSON, _ := json.Marshal(s.Tags)
		w.Write([]string{
			s.CapturedAt.Format(time.RFC3339),
			s.ControllerID,
			strconv.FormatUint(s.ClusterID, 10),
			s.ClusterName,
			s.ClusterType,
			s.DBVendor,
			s.NodeID,
			s.Hostname,
			strconv.Itoa(s.Port),
			s.NodeRole,
			s.NodeStatus,
			vcpu, ram, vol,
			string(tagsJSON),
		})
	}

	return nil
}
