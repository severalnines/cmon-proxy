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
	"time"
)

// StatusResponse is the response for the getMeteringStatus operation.
type StatusResponse struct {
	CollectorRunning  bool   `json:"collector_running"`
	LastCollection    string `json:"last_successful_collection,omitempty"`
	TotalSnapshots    int64  `json:"total_snapshots"`
	OldestSnapshot    string `json:"oldest_snapshot,omitempty"`
	DBSizeBytes       int64  `json:"db_size_bytes"`
	CollectionInterval string `json:"collection_interval"`
}

// GetStatus builds the metering status response from the storage backend.
func GetStatus(ctx context.Context, storage StorageBackend, collectorRunning bool, interval time.Duration) (*StatusResponse, error) {
	resp := &StatusResponse{
		CollectorRunning:   collectorRunning,
		CollectionInterval: interval.String(),
	}

	lastCollection, err := storage.GetConfig(ctx, ConfigLastSuccessfulCollection)
	if err != nil {
		return nil, err
	}
	resp.LastCollection = lastCollection

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

	return resp, nil
}
