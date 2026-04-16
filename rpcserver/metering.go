package rpcserver

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
	"archive/zip"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/severalnines/cmon-proxy/config"
	"github.com/severalnines/cmon-proxy/metering"
	"go.uber.org/zap"
)

const (
	defaultMeteringInterval    = time.Hour
	defaultMinActiveHours      = 24
)

var meteringSigningKey []byte
var meteringKeyID string

func initMetering(cfg *config.Config) {
	log := zap.L().Sugar()

	// Determine DB path.
	dbPath := cfg.MeteringDBPath
	if dbPath == "" {
		basedir := filepath.Dir(cfg.Filename)
		if basedir == "" || basedir == "." {
			basedir = "."
		}
		dbPath = filepath.Join(basedir, "metering.db")
	}

	// Parse interval.
	meteringInterval = defaultMeteringInterval
	if cfg.MeteringInterval != "" {
		d, err := time.ParseDuration(cfg.MeteringInterval)
		if err != nil {
			log.Warnf("[metering] invalid metering_interval %q, using default %s: %v", cfg.MeteringInterval, defaultMeteringInterval, err)
		} else {
			meteringInterval = d
		}
	}

	// Signing key.
	if cfg.MeteringSigningKey != "" {
		meteringSigningKey = []byte(cfg.MeteringSigningKey)
		meteringKeyID = cfg.MeteringKeyID
		if meteringKeyID == "" {
			meteringKeyID = "default"
		}
	}

	// Open storage.
	var err error
	meteringStorage, err = metering.NewSQLiteBackend(dbPath)
	if err != nil {
		log.Errorf("[metering] failed to open database at %s: %v (metering disabled)", dbPath, err)
		return
	}

	log.Infof("[metering] database opened at %s", dbPath)

	// Create collector using the default router.
	provider := metering.NewRouterAdapter(proxy.DefaultRouter())
	meteringCollector = metering.NewCollector(meteringStorage, provider, meteringInterval)
	meteringCollector.Start()

	log.Infof("[metering] collector started with interval %s", meteringInterval)
}

func handleMeteringStatus(ctx *gin.Context) {
	if meteringStorage == nil {
		ctx.JSON(http.StatusOK, &metering.StatusResponse{
			CollectorRunning: false,
		})
		return
	}

	resp, err := metering.GetStatus(ctx.Request.Context(), meteringStorage, meteringCollector != nil, meteringInterval)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, resp)
}

// reportRequest is the JSON body for report operations.
type reportRequest struct {
	Operation       string `json:"operation"`
	PeriodStart     string `json:"period_start,omitempty"`
	PeriodEnd       string `json:"period_end,omitempty"`
	Format          string `json:"format,omitempty"` // "json" or "csv"
	ReportID        int64  `json:"report_id,omitempty"`
	ForceRegenerate bool   `json:"force_regenerate,omitempty"`
}

func handleMeteringReports(ctx *gin.Context) {
	if meteringStorage == nil {
		ctx.JSON(http.StatusServiceUnavailable, gin.H{"error": "metering is not enabled"})
		return
	}

	var req reportRequest
	if ctx.Request.Method == http.MethodPost {
		if err := ctx.BindJSON(&req); err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: " + err.Error()})
			return
		}
	}

	switch req.Operation {
	case "generateReport":
		handleGenerateReport(ctx, req)
	case "listReports":
		handleListReports(ctx)
	case "verifyReport":
		handleVerifyReport(ctx, req)
	case "exportReport":
		handleExportReport(ctx, req)
	default:
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "unknown operation: " + req.Operation})
	}
}

func handleGenerateReport(ctx *gin.Context, req reportRequest) {
	periodStart, err := time.Parse(time.RFC3339, req.PeriodStart)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid period_start: " + err.Error()})
		return
	}
	periodEnd, err := time.Parse(time.RFC3339, req.PeriodEnd)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid period_end: " + err.Error()})
		return
	}

	rctx := ctx.Request.Context()

	// Check if a sealed report already exists.
	if !req.ForceRegenerate {
		existing, err := meteringStorage.GetReportByPeriod(rctx, periodStart, periodEnd)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if existing != nil {
			var reportData metering.ReportData
			json.Unmarshal([]byte(existing.ReportData), &reportData)
			ctx.JSON(http.StatusOK, gin.H{
				"report":    reportData,
				"report_id": existing.ID,
				"sealed":    true,
			})
			return
		}
	}

	// Determine next version.
	latestVersion, err := meteringStorage.GetLatestReportVersion(rctx, periodStart, periodEnd)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	nextVersion := latestVersion + 1

	// Generate report.
	gen := metering.NewReportGenerator(meteringStorage, defaultMinActiveHours)
	reportData, err := gen.Generate(rctx, periodStart, periodEnd, nextVersion)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "report generation failed: " + err.Error()})
		return
	}

	// Seal report.
	sealed, err := metering.SealReport(reportData, meteringSigningKey, meteringKeyID)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "sealing failed: " + err.Error()})
		return
	}

	// Store.
	report := &metering.BillingReport{
		ReportVersion: nextVersion,
		PeriodStart:   periodStart,
		PeriodEnd:     periodEnd,
		GeneratedAt:   time.Now().UTC(),
		ReportData:    sealed.CanonicalJSON,
		SHA256Hash:    sealed.SHA256Hash,
		Signature:     sealed.Signature,
		SigningKeyID:  sealed.SigningKeyID,
	}

	id, err := meteringStorage.InsertReport(rctx, report)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to store report: " + err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"report":    reportData,
		"report_id": id,
		"sealed":    true,
	})
}

func handleListReports(ctx *gin.Context) {
	reports, err := meteringStorage.ListReports(ctx.Request.Context())
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	type reportMeta struct {
		ID              int64  `json:"id"`
		ReportVersion   int    `json:"report_version"`
		PeriodStart     string `json:"period_start"`
		PeriodEnd       string `json:"period_end"`
		GeneratedAt     string `json:"generated_at"`
		SHA256Hash      string `json:"sha256_hash"`
	}

	var list []reportMeta
	for _, r := range reports {
		// Extract total_billable_nodes from report data for the summary.
		list = append(list, reportMeta{
			ID:            r.ID,
			ReportVersion: r.ReportVersion,
			PeriodStart:   r.PeriodStart.Format(time.RFC3339),
			PeriodEnd:     r.PeriodEnd.Format(time.RFC3339),
			GeneratedAt:   r.GeneratedAt.Format(time.RFC3339),
			SHA256Hash:    r.SHA256Hash,
		})
	}

	if list == nil {
		list = []reportMeta{}
	}

	ctx.JSON(http.StatusOK, gin.H{"reports": list})
}

func handleVerifyReport(ctx *gin.Context, req reportRequest) {
	if req.ReportID == 0 {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "report_id is required"})
		return
	}

	report, err := meteringStorage.GetReport(ctx.Request.Context(), req.ReportID)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if report == nil {
		ctx.JSON(http.StatusNotFound, gin.H{"error": "report not found"})
		return
	}

	hashOK, sigOK := metering.VerifySeal(report.ReportData, report.SHA256Hash, report.Signature, meteringSigningKey)

	ctx.JSON(http.StatusOK, gin.H{
		"report_id":       report.ID,
		"hash_valid":      hashOK,
		"signature_valid": sigOK,
		"verified_at":     time.Now().UTC().Format(time.RFC3339),
	})
}

func handleExportReport(ctx *gin.Context, req reportRequest) {
	if req.ReportID == 0 {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "report_id is required"})
		return
	}

	report, err := meteringStorage.GetReport(ctx.Request.Context(), req.ReportID)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if report == nil {
		ctx.JSON(http.StatusNotFound, gin.H{"error": "report not found"})
		return
	}

	format := req.Format
	if format == "" {
		format = "json"
	}

	switch format {
	case "json":
		ctx.Header("Content-Disposition", fmt.Sprintf("attachment; filename=metering-report-%d.json", report.ID))
		ctx.Data(http.StatusOK, "application/json", []byte(report.ReportData))

	case "csv":
		var reportData metering.ReportData
		if err := json.Unmarshal([]byte(report.ReportData), &reportData); err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to parse report data"})
			return
		}

		zipBuf, err := generateCSVZip(&reportData)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate CSV: " + err.Error()})
			return
		}

		ctx.Header("Content-Disposition", fmt.Sprintf("attachment; filename=metering-report-%d.zip", report.ID))
		ctx.Data(http.StatusOK, "application/zip", zipBuf)

	default:
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "unsupported format: " + format})
	}
}

func generateCSVZip(report *metering.ReportData) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	// summary.csv
	summaryFile, err := zw.Create("summary.csv")
	if err != nil {
		return nil, err
	}
	sw := csv.NewWriter(summaryFile)
	sw.Write([]string{"cluster_type", "db_vendor", "max_concurrent_nodes", "max_vcpu", "max_ram_gb", "max_volume_gb"})
	for _, tv := range report.ByTypeAndVendor {
		sw.Write([]string{
			tv.ClusterType,
			tv.DBVendor,
			strconv.Itoa(tv.MaxConcurrentNodes),
			strconv.Itoa(tv.MaxVCPU),
			strconv.Itoa(tv.MaxRAMGB),
			strconv.Itoa(tv.MaxVolumeGB),
		})
	}
	sw.Flush()

	// node_details.csv
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
			nd.NodeID,
			nd.ControllerID,
			strconv.FormatUint(nd.ClusterID, 10),
			nd.ClusterName,
			nd.ClusterType,
			nd.DBVendor,
			nd.NodeRole,
			strconv.Itoa(nd.ActiveHours),
			strconv.Itoa(nd.MaxVCPU),
			nd.MaxVCPUObservedAt,
			strconv.Itoa(nd.MaxRAMMB),
			nd.MaxRAMObservedAt,
			strconv.Itoa(nd.MaxVolumeGB),
			nd.MaxVolumeObservedAt,
		})
	}
	dw.Flush()

	if err := zw.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
