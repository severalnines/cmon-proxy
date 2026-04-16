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
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// SQLiteBackend implements StorageBackend using SQLite.
type SQLiteBackend struct {
	db   *sql.DB
	path string
}

// NewSQLiteBackend opens or creates a SQLite database at the given path
// and ensures the schema is initialized.
func NewSQLiteBackend(dbPath string) (*SQLiteBackend, error) {
	db, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(wal)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	// SQLite works best with a single writer connection.
	db.SetMaxOpenConns(1)

	s := &SQLiteBackend{db: db, path: dbPath}
	if err := s.initSchema(); err != nil {
		db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}

	return s, nil
}

func (s *SQLiteBackend) initSchema() error {
	_, err := s.db.Exec(schemaSQL)
	return err
}

const schemaSQL = `
CREATE TABLE IF NOT EXISTS node_snapshots (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    captured_at   TIMESTAMP NOT NULL,
    controller_id TEXT NOT NULL,
    cluster_id    INTEGER NOT NULL,
    cluster_name  TEXT NOT NULL,
    cluster_type  TEXT NOT NULL,
    db_vendor     TEXT NOT NULL,
    node_id       TEXT NOT NULL,
    hostname      TEXT NOT NULL,
    port          INTEGER NOT NULL,
    node_role     TEXT NOT NULL,
    node_status   TEXT NOT NULL,
    vcpu          INTEGER,
    ram_mb        INTEGER,
    volume_gb     INTEGER,
    tags          TEXT
);

CREATE INDEX IF NOT EXISTS idx_snapshots_period  ON node_snapshots(captured_at, node_id);
CREATE INDEX IF NOT EXISTS idx_snapshots_node    ON node_snapshots(node_id, captured_at);
CREATE INDEX IF NOT EXISTS idx_snapshots_cluster ON node_snapshots(cluster_id, controller_id, captured_at);

CREATE TABLE IF NOT EXISTS billing_reports (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    report_version  INTEGER NOT NULL DEFAULT 1,
    period_start    TIMESTAMP NOT NULL,
    period_end      TIMESTAMP NOT NULL,
    generated_at    TIMESTAMP NOT NULL,
    report_data     TEXT NOT NULL,
    sha256_hash     TEXT NOT NULL,
    signature       TEXT,
    signing_key_id  TEXT,
    UNIQUE(period_start, period_end, report_version)
);

CREATE TABLE IF NOT EXISTS metering_config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
`

// InsertSnapshots batch-inserts node snapshots in a single transaction.
func (s *SQLiteBackend) InsertSnapshots(ctx context.Context, snapshots []NodeSnapshot) error {
	if len(snapshots) == 0 {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO node_snapshots
			(captured_at, controller_id, cluster_id, cluster_name, cluster_type,
			 db_vendor, node_id, hostname, port, node_role, node_status,
			 vcpu, ram_mb, volume_gb, tags)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("prepare: %w", err)
	}
	defer stmt.Close()

	for _, snap := range snapshots {
		tagsJSON, err := json.Marshal(snap.Tags)
		if err != nil {
			return fmt.Errorf("marshal tags: %w", err)
		}

		_, err = stmt.ExecContext(ctx,
			snap.CapturedAt.UTC().Format(time.RFC3339),
			snap.ControllerID,
			snap.ClusterID,
			snap.ClusterName,
			snap.ClusterType,
			snap.DBVendor,
			snap.NodeID,
			snap.Hostname,
			snap.Port,
			snap.NodeRole,
			snap.NodeStatus,
			snap.VCPU,
			snap.RAMMB,
			snap.VolumeGB,
			string(tagsJSON),
		)
		if err != nil {
			return fmt.Errorf("insert snapshot for node %s: %w", snap.NodeID, err)
		}
	}

	return tx.Commit()
}

// QuerySnapshots returns snapshots matching the given filter.
func (s *SQLiteBackend) QuerySnapshots(ctx context.Context, filter SnapshotFilter) ([]NodeSnapshot, error) {
	query := "SELECT id, captured_at, controller_id, cluster_id, cluster_name, cluster_type, db_vendor, node_id, hostname, port, node_role, node_status, vcpu, ram_mb, volume_gb, tags FROM node_snapshots"

	var conditions []string
	var args []interface{}

	if filter.PeriodStart != nil {
		conditions = append(conditions, "captured_at >= ?")
		args = append(args, filter.PeriodStart.UTC().Format(time.RFC3339))
	}
	if filter.PeriodEnd != nil {
		conditions = append(conditions, "captured_at <= ?")
		args = append(args, filter.PeriodEnd.UTC().Format(time.RFC3339))
	}
	if filter.NodeID != nil {
		conditions = append(conditions, "node_id = ?")
		args = append(args, *filter.NodeID)
	}
	if filter.ControllerID != nil {
		conditions = append(conditions, "controller_id = ?")
		args = append(args, *filter.ControllerID)
	}
	if filter.ClusterID != nil {
		conditions = append(conditions, "cluster_id = ?")
		args = append(args, *filter.ClusterID)
	}
	if len(filter.NodeStatuses) > 0 {
		placeholders := make([]string, len(filter.NodeStatuses))
		for i, status := range filter.NodeStatuses {
			placeholders[i] = "?"
			args = append(args, status)
		}
		conditions = append(conditions, "node_status IN ("+strings.Join(placeholders, ",")+")")
	}
	if len(filter.NodeRoles) > 0 {
		placeholders := make([]string, len(filter.NodeRoles))
		for i, role := range filter.NodeRoles {
			placeholders[i] = "?"
			args = append(args, role)
		}
		conditions = append(conditions, "node_role IN ("+strings.Join(placeholders, ",")+")")
	}

	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}
	query += " ORDER BY captured_at ASC"

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query snapshots: %w", err)
	}
	defer rows.Close()

	return scanSnapshots(rows)
}

// parseTimestamp parses a timestamp string stored in SQLite.
func parseTimestamp(s string) (time.Time, error) {
	for _, layout := range []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05-07:00",
		"2006-01-02 15:04:05",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("cannot parse timestamp %q", s)
}

func scanSnapshots(rows *sql.Rows) ([]NodeSnapshot, error) {
	var results []NodeSnapshot
	for rows.Next() {
		var snap NodeSnapshot
		var capturedAtStr string
		var tagsJSON sql.NullString
		var vcpu, ramMB, volGB sql.NullInt64

		err := rows.Scan(
			&snap.ID,
			&capturedAtStr,
			&snap.ControllerID,
			&snap.ClusterID,
			&snap.ClusterName,
			&snap.ClusterType,
			&snap.DBVendor,
			&snap.NodeID,
			&snap.Hostname,
			&snap.Port,
			&snap.NodeRole,
			&snap.NodeStatus,
			&vcpu,
			&ramMB,
			&volGB,
			&tagsJSON,
		)
		if err != nil {
			return nil, fmt.Errorf("scan snapshot: %w", err)
		}

		snap.CapturedAt, err = parseTimestamp(capturedAtStr)
		if err != nil {
			return nil, err
		}

		if vcpu.Valid {
			v := int(vcpu.Int64)
			snap.VCPU = &v
		}
		if ramMB.Valid {
			v := int(ramMB.Int64)
			snap.RAMMB = &v
		}
		if volGB.Valid {
			v := int(volGB.Int64)
			snap.VolumeGB = &v
		}
		if tagsJSON.Valid && tagsJSON.String != "" {
			json.Unmarshal([]byte(tagsJSON.String), &snap.Tags)
		}

		results = append(results, snap)
	}
	return results, rows.Err()
}

// CountSnapshots returns the total number of snapshot rows.
func (s *SQLiteBackend) CountSnapshots(ctx context.Context) (int64, error) {
	var count int64
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM node_snapshots").Scan(&count)
	return count, err
}

// OldestSnapshotTime returns the timestamp of the oldest snapshot, or nil if empty.
func (s *SQLiteBackend) OldestSnapshotTime(ctx context.Context) (*time.Time, error) {
	var ts sql.NullString
	err := s.db.QueryRowContext(ctx, "SELECT MIN(captured_at) FROM node_snapshots").Scan(&ts)
	if err != nil {
		return nil, err
	}
	if !ts.Valid || ts.String == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339Nano, ts.String)
	if err != nil {
		// Try alternate SQLite datetime format.
		t, err = time.Parse("2006-01-02 15:04:05-07:00", ts.String)
		if err != nil {
			t, err = time.Parse("2006-01-02 15:04:05", ts.String)
			if err != nil {
				return nil, fmt.Errorf("parse oldest snapshot time %q: %w", ts.String, err)
			}
		}
	}
	return &t, nil
}

// DeleteSnapshotsBefore removes all snapshots older than the given time.
// Returns the number of deleted rows.
func (s *SQLiteBackend) DeleteSnapshotsBefore(ctx context.Context, before time.Time) (int64, error) {
	result, err := s.db.ExecContext(ctx, "DELETE FROM node_snapshots WHERE captured_at < ?", before.UTC().Format(time.RFC3339))
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// InsertReport inserts a sealed billing report and returns its ID.
func (s *SQLiteBackend) InsertReport(ctx context.Context, report *BillingReport) (int64, error) {
	result, err := s.db.ExecContext(ctx, `
		INSERT INTO billing_reports
			(report_version, period_start, period_end, generated_at, report_data, sha256_hash, signature, signing_key_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		report.ReportVersion,
		report.PeriodStart.UTC().Format(time.RFC3339),
		report.PeriodEnd.UTC().Format(time.RFC3339),
		report.GeneratedAt.UTC().Format(time.RFC3339),
		report.ReportData,
		report.SHA256Hash,
		report.Signature,
		report.SigningKeyID,
	)
	if err != nil {
		return 0, fmt.Errorf("insert report: %w", err)
	}
	return result.LastInsertId()
}

// GetReport returns a billing report by ID.
func (s *SQLiteBackend) GetReport(ctx context.Context, id int64) (*BillingReport, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, report_version, period_start, period_end, generated_at, report_data, sha256_hash, signature, signing_key_id
		FROM billing_reports WHERE id = ?`, id)
	return scanReport(row)
}

// GetReportByPeriod returns the latest version of a report for a given period.
func (s *SQLiteBackend) GetReportByPeriod(ctx context.Context, periodStart, periodEnd time.Time) (*BillingReport, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, report_version, period_start, period_end, generated_at, report_data, sha256_hash, signature, signing_key_id
		FROM billing_reports
		WHERE period_start = ? AND period_end = ?
		ORDER BY report_version DESC LIMIT 1`,
		periodStart.UTC().Format(time.RFC3339), periodEnd.UTC().Format(time.RFC3339))
	return scanReport(row)
}

// GetLatestReportVersion returns the highest report version for a given period, or 0 if none exists.
func (s *SQLiteBackend) GetLatestReportVersion(ctx context.Context, periodStart, periodEnd time.Time) (int, error) {
	var version sql.NullInt64
	err := s.db.QueryRowContext(ctx, `
		SELECT MAX(report_version) FROM billing_reports
		WHERE period_start = ? AND period_end = ?`,
		periodStart.UTC().Format(time.RFC3339), periodEnd.UTC().Format(time.RFC3339)).Scan(&version)
	if err != nil {
		return 0, err
	}
	if !version.Valid {
		return 0, nil
	}
	return int(version.Int64), nil
}

// ListReports returns metadata for all sealed reports ordered by period.
func (s *SQLiteBackend) ListReports(ctx context.Context) ([]BillingReport, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, report_version, period_start, period_end, generated_at, report_data, sha256_hash, signature, signing_key_id
		FROM billing_reports ORDER BY period_start DESC, report_version DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []BillingReport
	for rows.Next() {
		var r BillingReport
		var periodStartStr, periodEndStr, generatedAtStr string
		var sig, keyID sql.NullString
		err := rows.Scan(&r.ID, &r.ReportVersion, &periodStartStr, &periodEndStr, &generatedAtStr, &r.ReportData, &r.SHA256Hash, &sig, &keyID)
		if err != nil {
			return nil, fmt.Errorf("scan report: %w", err)
		}
		if r.PeriodStart, err = parseTimestamp(periodStartStr); err != nil {
			return nil, err
		}
		if r.PeriodEnd, err = parseTimestamp(periodEndStr); err != nil {
			return nil, err
		}
		if r.GeneratedAt, err = parseTimestamp(generatedAtStr); err != nil {
			return nil, err
		}
		if sig.Valid {
			r.Signature = sig.String
		}
		if keyID.Valid {
			r.SigningKeyID = keyID.String
		}
		results = append(results, r)
	}
	return results, rows.Err()
}

func scanReport(row *sql.Row) (*BillingReport, error) {
	var r BillingReport
	var periodStartStr, periodEndStr, generatedAtStr string
	var sig, keyID sql.NullString
	err := row.Scan(&r.ID, &r.ReportVersion, &periodStartStr, &periodEndStr, &generatedAtStr, &r.ReportData, &r.SHA256Hash, &sig, &keyID)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scan report: %w", err)
	}
	if r.PeriodStart, err = parseTimestamp(periodStartStr); err != nil {
		return nil, err
	}
	if r.PeriodEnd, err = parseTimestamp(periodEndStr); err != nil {
		return nil, err
	}
	if r.GeneratedAt, err = parseTimestamp(generatedAtStr); err != nil {
		return nil, err
	}
	if sig.Valid {
		r.Signature = sig.String
	}
	if keyID.Valid {
		r.SigningKeyID = keyID.String
	}
	return &r, nil
}

// GetConfig reads a configuration value by key.
func (s *SQLiteBackend) GetConfig(ctx context.Context, key string) (string, error) {
	var value string
	err := s.db.QueryRowContext(ctx, "SELECT value FROM metering_config WHERE key = ?", key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return value, err
}

// SetConfig upserts a configuration value.
func (s *SQLiteBackend) SetConfig(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO metering_config (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// Close closes the database connection.
func (s *SQLiteBackend) Close() error {
	return s.db.Close()
}

// DatabaseSize returns the size of the SQLite database file in bytes.
func (s *SQLiteBackend) DatabaseSize(ctx context.Context) (int64, error) {
	fi, err := os.Stat(s.path)
	if err != nil {
		return 0, err
	}
	return fi.Size(), nil
}
