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
	"time"
)

// NodeSnapshot represents a point-in-time capture of an eligible node's state.
// One row is inserted per eligible node per hourly collection tick.
type NodeSnapshot struct {
	ID           int64     `json:"id"`
	CapturedAt   time.Time `json:"captured_at"`
	ControllerID string    `json:"controller_id"`
	ClusterID    uint64    `json:"cluster_id"`
	ClusterName  string    `json:"cluster_name"`
	ClusterType  string    `json:"cluster_type"`
	DBVendor     string    `json:"db_vendor"`
	NodeID       string    `json:"node_id"` // "{controller_id}:{private_ip}"
	Hostname     string    `json:"hostname"`
	Port         int       `json:"port"`
	NodeRole     string    `json:"node_role"`   // "database" or "proxysql"
	NodeStatus   string    `json:"node_status"` // "active", "stopped", "removed"
	VCPU         *int      `json:"vcpu,omitempty"`
	RAMMB        *int      `json:"ram_mb,omitempty"`
	VolumeGB     *int      `json:"volume_gb,omitempty"`
	Tags         []string  `json:"tags,omitempty"`
}

// BillingReport represents a sealed billing report for a specific period.
type BillingReport struct {
	ID            int64     `json:"id"`
	ReportVersion int       `json:"report_version"`
	PeriodStart   time.Time `json:"period_start"`
	PeriodEnd     time.Time `json:"period_end"`
	GeneratedAt   time.Time `json:"generated_at"`
	ReportData    string    `json:"report_data"`
	SHA256Hash    string    `json:"sha256_hash"`
	Signature     string    `json:"signature,omitempty"`
	SigningKeyID  string    `json:"signing_key_id,omitempty"`
}

// Node roles for eligible nodes.
const (
	NodeRoleDatabase = "database"
	NodeRoleProxySQL = "proxysql"
)

// Node statuses.
const (
	NodeStatusActive  = "active"
	NodeStatusStopped = "stopped"
	NodeStatusRemoved = "removed"
)

// EligibleDBClassNames maps CMON host class names to whether they are eligible database nodes.
var EligibleDBClassNames = map[string]bool{
	"CmonMySqlHost":         true,
	"CmonGaleraHost":        true,
	"CmonElasticHost":       true,
	"CmonRedisHost":         true,
	"CmonRedisSentinelHost": true,
	"CmonGroupReplHost":     true,
	"CmonMongoHost":         true,
	"CmonNdbHost":           true,
	"CmonPostgreSqlHost":    true,
}

// EligibleProxyClassNames maps CMON host class names to whether they are eligible proxy nodes.
var EligibleProxyClassNames = map[string]bool{
	"CmonProxySqlHost": true,
}

// IsEligibleNode returns true if the given class name represents a billable node.
func IsEligibleNode(className string) bool {
	return EligibleDBClassNames[className] || EligibleProxyClassNames[className]
}

// NodeRoleFromClassName returns the metering node role for a given CMON host class name.
func NodeRoleFromClassName(className string) string {
	if EligibleProxyClassNames[className] {
		return NodeRoleProxySQL
	}
	return NodeRoleDatabase
}

// NormalizeVendor maps CMON vendor strings to normalized metering vendor names.
func NormalizeVendor(vendor string) string {
	switch vendor {
	case "percona", "Percona":
		return "percona"
	case "oracle", "Oracle":
		return "oracle"
	case "mariadb", "MariaDB":
		return "mariadb"
	case "10gen", "MongoDB", "mongodb":
		return "mongodb"
	case "redis", "Redis", "Redis Labs":
		return "redis"
	case "microsoft", "Microsoft":
		return "microsoft"
	case "elastic", "Elastic":
		return "elastic"
	case "postgresql", "PostgreSQL":
		return "postgresql"
	case "valkey", "Valkey":
		return "valkey"
	case "timescaledb", "TimescaleDB":
		return "timescaledb"
	default:
		if vendor == "" {
			return "community"
		}
		return vendor
	}
}
