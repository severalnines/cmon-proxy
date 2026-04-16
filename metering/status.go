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
	"strconv"
	"time"
)

// StatusResponse is the response for the getMeteringStatus operation.
type StatusResponse struct {
	CollectorRunning    bool   `json:"collector_running"`
	CollectionHealthy   bool   `json:"collection_healthy"`
	HealthStatus        string `json:"health_status"`
	LastCollection      string `json:"last_successful_collection,omitempty"`
	LastCollectionError string `json:"last_collection_error,omitempty"`
	TotalSnapshots      int64  `json:"total_snapshots"`
	OldestSnapshot      string `json:"oldest_snapshot,omitempty"`
	DBSizeBytes         int64  `json:"db_size_bytes"`
	CollectionInterval  string `json:"collection_interval"`
	RetentionMonths     int    `json:"retention_months"`
	LastCleanup         string `json:"last_retention_cleanup,omitempty"`
	LastCleanupDeleted  int64  `json:"last_cleanup_deleted_rows"`
	LastCleanupError    string `json:"last_cleanup_error,omitempty"`
}

// GetStatus builds the metering status response from the storage backend.
func GetStatus(ctx context.Context, storage StorageBackend, collectorRunning bool, interval time.Duration) (*StatusResponse, error) {
	resp := &StatusResponse{
		CollectorRunning:   collectorRunning,
		CollectionHealthy:  collectorRunning,
		HealthStatus:       "ok",
		CollectionInterval: interval.String(),
		RetentionMonths:    DefaultRetentionMonths,
	}

	lastCollection, err := storage.GetConfig(ctx, ConfigLastSuccessfulCollection)
	if err != nil {
		return nil, err
	}
	resp.LastCollection = lastCollection

	lastCollectionError, err := storage.GetConfig(ctx, ConfigLastCollectionError)
	if err != nil {
		return nil, err
	}
	resp.LastCollectionError = lastCollectionError

	count, err := storage.CountSnapshots(ctx)
	if err != nil {
		return nil, err
	}
	resp.TotalSnapshots = count

	oldest, err := storage.OldestSnapshotTime(ctx)
	if err != nil {
		return nil, err
	}
	if oldest != nil {
		resp.OldestSnapshot = oldest.Format(time.RFC3339)
	}

	size, err := storage.DatabaseSize(ctx)
	if err != nil {
		return nil, err
	}
	resp.DBSizeBytes = size

	if retentionMonths, err := getConfigInt(ctx, storage, ConfigRetentionMonths, DefaultRetentionMonths); err != nil {
		return nil, err
	} else {
		resp.RetentionMonths = retentionMonths
	}

	lastCleanup, err := storage.GetConfig(ctx, ConfigLastRetentionCleanup)
	if err != nil {
		return nil, err
	}
	resp.LastCleanup = lastCleanup

	if deletedRows, err := getConfigInt64(ctx, storage, ConfigLastCleanupDeletedRows, 0); err != nil {
		return nil, err
	} else {
		resp.LastCleanupDeleted = deletedRows
	}

	lastCleanupError, err := storage.GetConfig(ctx, ConfigLastCleanupError)
	if err != nil {
		return nil, err
	}
	resp.LastCleanupError = lastCleanupError

	if !collectorRunning {
		resp.CollectionHealthy = false
		resp.HealthStatus = "error"
	}
	if resp.LastCollection == "" {
		resp.CollectionHealthy = false
		if resp.HealthStatus != "error" {
			resp.HealthStatus = "warning"
		}
	}
	if resp.LastCollection != "" {
		if lastCollectionAt, err := parseTimestamp(resp.LastCollection); err == nil && interval > 0 && time.Since(lastCollectionAt) > 2*interval {
			resp.CollectionHealthy = false
			if resp.HealthStatus != "error" {
				resp.HealthStatus = "warning"
			}
		}
	}
	if resp.LastCollectionError != "" || resp.LastCleanupError != "" {
		resp.CollectionHealthy = false
		if resp.HealthStatus != "error" {
			resp.HealthStatus = "warning"
		}
	}

	return resp, nil
}

func getConfigInt(ctx context.Context, storage StorageBackend, key string, fallback int) (int, error) {
	raw, err := storage.GetConfig(ctx, key)
	if err != nil {
		return 0, err
	}
	if raw == "" {
		return fallback, nil
	}

	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, err
	}
	return value, nil
}

func getConfigInt64(ctx context.Context, storage StorageBackend, key string, fallback int64) (int64, error) {
	raw, err := storage.GetConfig(ctx, key)
	if err != nil {
		return 0, err
	}
	if raw == "" {
		return fallback, nil
	}

	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, err
	}
	return value, nil
}
