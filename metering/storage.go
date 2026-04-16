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

// StorageBackend defines the persistence interface for metering data.
// Implementations must be safe for concurrent use.
type StorageBackend interface {
	// Snapshot operations
	InsertSnapshots(ctx context.Context, snapshots []NodeSnapshot) error
	QuerySnapshots(ctx context.Context, filter SnapshotFilter) ([]NodeSnapshot, error)
	CountSnapshots(ctx context.Context) (int64, error)
	OldestSnapshotTime(ctx context.Context) (*time.Time, error)
	DeleteSnapshotsBefore(ctx context.Context, before time.Time) (int64, error)

	// Report operations
	InsertReport(ctx context.Context, report *BillingReport) (int64, error)
	GetReport(ctx context.Context, id int64) (*BillingReport, error)
	GetReportByPeriod(ctx context.Context, periodStart, periodEnd time.Time) (*BillingReport, error)
	GetLatestReportVersion(ctx context.Context, periodStart, periodEnd time.Time) (int, error)
	ListReports(ctx context.Context) ([]BillingReport, error)

	// Config operations
	GetConfig(ctx context.Context, key string) (string, error)
	SetConfig(ctx context.Context, key, value string) error

	// Lifecycle
	Close() error

	// DatabaseSize returns the size of the storage in bytes.
	DatabaseSize(ctx context.Context) (int64, error)
}

// SnapshotFilter defines query parameters for filtering snapshots.
type SnapshotFilter struct {
	PeriodStart  *time.Time
	PeriodEnd    *time.Time
	NodeID       *string
	ControllerID *string
	ClusterID    *uint64
	NodeStatuses []string // filter by one or more statuses
	NodeRoles    []string // filter by one or more roles
}

// Config keys stored in metering_config.
const (
	ConfigBillingPeriodMonths  = "billing_period_months"
	ConfigMinActiveHours       = "min_active_hours"
	ConfigSigningKeyID         = "signing_key_id"
	ConfigRetentionMonths      = "retention_months"
	ConfigLastSuccessfulCollection = "last_successful_collection"
)
