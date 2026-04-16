# Usage Metering — Architecture

## Overview

The usage metering system tracks database node usage across ClusterControl deployments for billing purposes. It runs as a module inside cmon-proxy, collecting hourly snapshots of eligible nodes from all connected CMON controllers and producing sealed billing reports.

**Primary audiences:**
1. **Severalnines** — bill MSP/CSP customers based on eligible node counts
2. **MSP/CSP operators** — bill their own customers based on per-tenant usage (Phase 3)

## System Architecture

```
cmon-proxy process
│
├── Router (existing)
│   ├── Sync() — discovers/manages CMON controller connections
│   └── GetAllClusterInfo() — fetches cluster+host data from all controllers
│
├── metering/ package (new)
│   │
│   ├── MeteringCollector
│   │   ├── Hourly ticker (configurable via METERING_INTERVAL)
│   │   ├── RouterAdapter.FetchAllClusters()
│   │   │   ├── Router.GetAllClusterInfo(forceUpdate=true)
│   │   │   ├── Client.GetStatByName(memorystat) per cluster
│   │   │   └── Client.GetStatByName(diskstat) per cluster
│   │   ├── Filters to eligible nodes (DB hosts + ProxySQL)
│   │   ├── Diffs against previous snapshot (detect removed nodes)
│   │   └── Batch-inserts into StorageBackend
│   │
│   ├── ReportGenerator
│   │   ├── Queries raw snapshots for a billing period
│   │   ├── Identifies billable nodes (≥24h active/stopped)
│   │   ├── Computes high-water marks (max vCPU, RAM, volume)
│   │   ├── Computes max concurrent nodes per type+vendor
│   │   └── Detects resource changes between consecutive snapshots
│   │
│   ├── Sealing
│   │   ├── Canonical JSON serialization
│   │   ├── SHA-256 hash
│   │   └── HMAC-SHA256 signature (configurable key)
│   │
│   ├── StorageBackend (interface)
│   │   └── SQLiteBackend (default, WAL mode, pure Go driver)
│   │
│   └── RouterAdapter
│       └── Bridges Router → ClusterDataProvider interface
│
└── rpcserver/metering.go
    ├── initMetering() — lifecycle setup on proxy startup
    ├── handleMeteringStatus() — GET/POST /proxy/metering/status
    └── handleMeteringReports() — POST /proxy/metering/reports
```

## Data Flow

### Collection (hourly)

```
CMON Controller 1 ──┐
CMON Controller 2 ──┤── Router.GetAllClusterInfo(forceUpdate=true)
CMON Controller N ──┘        │
                             ▼
                    RouterAdapter.FetchAllClusters()
                             │
                    ┌────────┴────────┐
                    │  For each cluster:
                    │  GetStatByName(memorystat) → ramtotal per hostid
                    │  GetStatByName(diskstat)   → disk total per hostid
                    └────────┬────────┘
                             │
                    MeteringCollector.collect()
                             │
                    ┌────────┴────────┐
                    │  Filter: eligible nodes only
                    │  (DB hosts + ProxySQL, skip controller/prometheus)
                    │
                    │  Diff: compare against previous snapshot
                    │  - New nodes → status "active"
                    │  - Gone nodes → status "removed"
                    │  - Unreachable controller → skip (no false removals)
                    └────────┬────────┘
                             │
                    SQLiteBackend.InsertSnapshots()
                             │
                             ▼
                    node_snapshots table (append-only)
```

### Report Generation (on-demand)

```
API: POST /proxy/metering/reports
     { "operation": "generateReport", "period_start": "...", "period_end": "..." }
                             │
                    ReportGenerator.Generate()
                             │
                    ┌────────┴────────┐
                    │  1. Query all snapshots in period
                    │  2. Count active hours per node
                    │  3. Filter: ≥24h → billable
                    │  4. Per-node: max vCPU/RAM/volume + first-observed timestamps
                    │  5. Per type+vendor: max concurrent active nodes
                    │  6. Detect resource changes (consecutive snapshot diffs)
                    └────────┬────────┘
                             │
                    SealReport()
                    ├── Canonical JSON (sorted keys, no whitespace)
                    ├── SHA-256(report_data) → sha256_hash
                    └── HMAC-SHA256(hash, signing_key) → signature
                             │
                    SQLiteBackend.InsertReport()
                             │
                             ▼
                    billing_reports table (immutable, versioned)
```

## Data Model

### node_snapshots (event store, append-only)

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | Auto-increment |
| captured_at | TIMESTAMP | When this snapshot was taken |
| controller_id | TEXT | Controller URL or xid |
| cluster_id | INTEGER | CID within the controller |
| cluster_name | TEXT | Human-readable cluster name |
| cluster_type | TEXT | "GALERA", "REPLICATION", "POSTGRESQL_SINGLE", etc. |
| db_vendor | TEXT | Normalized: "percona", "oracle", "mariadb", "postgresql", etc. |
| node_id | TEXT | `"{controller_id}:{private_ip}"` — stable identifier |
| hostname | TEXT | Host name |
| port | INTEGER | Service port |
| node_role | TEXT | "database" or "proxysql" |
| node_status | TEXT | "active", "stopped", or "removed" |
| vcpu | INTEGER | vCPU count (nil if unavailable) |
| ram_mb | INTEGER | Total RAM in MB (from memorystat) |
| volume_gb | INTEGER | Data volume in GB (from diskstat, largest mount) |
| tags | TEXT | JSON array of cluster tags |

### billing_reports (sealed, immutable)

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | Auto-increment |
| report_version | INTEGER | Increments on regeneration |
| period_start | TIMESTAMP | Billing period start |
| period_end | TIMESTAMP | Billing period end |
| generated_at | TIMESTAMP | When the report was created |
| report_data | TEXT | Full canonical JSON report |
| sha256_hash | TEXT | SHA-256 of report_data |
| signature | TEXT | HMAC-SHA256 signature |
| signing_key_id | TEXT | Identifies which key signed it |

### metering_config (key-value settings)

Stores runtime state like `last_successful_collection`.

## Eligible Node Classification

A node is eligible for metering if its CMON `class_name` is one of:

| Class Name | Node Role |
|------------|-----------|
| CmonMySqlHost | database |
| CmonGaleraHost | database |
| CmonGroupReplHost | database |
| CmonPostgreSqlHost | database |
| CmonMongoHost | database |
| CmonRedisHost | database |
| CmonRedisSentinelHost | database |
| CmonElasticHost | database |
| CmonNdbHost | database |
| CmonMsSqlHost | database |
| CmonProxySqlHost | proxysql |

Excluded: `CmonHost` (controller), `CmonPrometheusHost`, `CmonHaProxyHost`, `CmonMaxScaleHost`.

## Billable Node Rules

A node is billable for a billing period if:
1. It is an eligible node (above)
2. It has ≥24 cumulative hours in "active" or "stopped" status during the period

Stopped nodes count toward billing until removed from the cluster.

## Cryptographic Sealing

Reports are tamper-evident:
1. Report JSON is canonicalized (sorted keys, no whitespace — deterministic)
2. SHA-256 hash computed over the canonical JSON
3. HMAC-SHA256 signature computed over the hash using a configurable signing key
4. Both hash and signature stored alongside the report
5. Verification recomputes and compares (constant-time comparison for signature)

Key rotation is supported: each report records the `signing_key_id` used, so old reports can be verified with their original key.

## Known Limitations

- **vCPU**: Not available from the CMON stat API. The `cpustat` endpoint returns aggregated CPU metrics without a core count. Requires a CMON API enhancement to expose `processors` on host objects.
- **Volume size**: Uses the largest disk mount as a heuristic for the data volume. May overcount if non-data mounts are larger.
- **Hardware stats**: Depend on CMON's host collector being active. Nodes without recent stats will have nil values for RAM/volume.

## Package Structure

```
metering/
├── models.go           Data types, eligible node maps, vendor normalization
├── storage.go          StorageBackend interface, SnapshotFilter, config keys
├── sqlite.go           SQLite implementation (WAL, RFC3339 timestamps)
├── collector.go        MeteringCollector goroutine, node diff logic
├── router_adapter.go   RouterAdapter (Router → ClusterDataProvider + stat collection)
├── report.go           ReportGenerator (aggregation, high-water marks, concurrency)
├── sealing.go          Canonical JSON, SHA-256, HMAC-SHA256
├── status.go           StatusResponse builder
├── sqlite_test.go      18 storage tests
├── collector_test.go   12 collector tests
├── report_test.go      9 report generator tests
├── sealing_test.go     9 sealing tests
└── integration_test.go 5 live tests (requires CMON_ENDPOINT env var)

rpcserver/
└── metering.go         Lifecycle init, HTTP handlers, CSV export
```
