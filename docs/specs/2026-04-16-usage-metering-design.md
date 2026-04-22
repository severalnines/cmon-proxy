# Usage Metering for ClusterControl — Design Spec

> **⚠️ SUPERSEDED — historical v1 design.** This spec describes the original "metering embedded inside cmon-proxy" architecture (CLUS-6418 Phase 1). The shipped architecture is v2: metering is decoupled into a standalone `cmon-telemetry` service that cmon-proxy emits to over OTLP (CLUS-7328). Claims in this document about a `metering/` package inside cmon-proxy, `node_snapshots` tables owned by cmon-proxy, and `/v2/metering/` endpoints on the proxy no longer reflect the code — all of that now lives in cmon-telemetry.
>
> **Current source of truth:** `docs/ARCHITECTURE-METERING-OPENTELEMETRY.md` (high-level) and `docs/README-OPENTELEMETRY.md` (operator guide).
>
> Preserved for historical context — useful for understanding the design evolution and the rationale behind the v1→v2 pivot.

## Workflow

- **Branch/worktree:** `CLUS-6418` (in `cmon-proxy/` subproject)
- **Jira epic:** [CLUS-6418](https://severalnines.atlassian.net/browse/CLUS-6418) — create Story issues under this epic for each phase/task
- **Commit message format:** All commit messages prefixed with `CLUS-6418` on the first line (e.g., `CLUS-6418 Add StorageBackend interface and SQLite adapter`)
- **Jira subtask tracking:** Create Jira stories before starting work on each phase; update status as work progresses

### Jira Stories to Create

| Phase | Jira Story Title | Type |
|---|---|---|
| Phase 1a | StorageBackend interface + SQLite adapter | Story |
| Phase 1b | MeteringCollector hourly snapshot collection | Story |
| Phase 1c | Metering status API endpoint + proxy lifecycle integration | Story |
| Phase 2a | Billing report generation + aggregation queries | Story |
| Phase 2b | Cryptographic sealing + report verification | Story |
| Phase 2c | Report API endpoints (generate, list, verify, export) | Story |
| Phase 3 | Customer-level filtering (tags, cluster IDs, cluster names) | Story |
| Phase 4 | UI reports page + integrations | Story |

## Context

MSP/CSP customers (e.g., Airtel, SITE) use ClusterControl as a backend for their DBaaS/Managed Services. Severalnines needs an automated way to measure usage across billing periods to:

1. **Bill MSP/CSPs** based on count of eligible nodes managed by ClusterControl
2. **Enable MSP/CSPs to bill their own customers** based on per-tenant usage breakdowns

Requirements: [CLUS-6418](https://severalnines.atlassian.net/browse/CLUS-6418) / [Confluence spec](https://severalnines.atlassian.net/wiki/spaces/S9SCLUS/pages/3581050881/Billing+usage+reports+in+ClusterControl)

## Design Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Collection point | cmon-proxy (Go) | Already aggregates N controllers; faster to iterate than C++ |
| Storage backend | Configurable interface, SQLite default | Zero-dependency for Phase 1; swap to PostgreSQL later for HA |
| Architecture pattern | Event-sourced (append-only snapshots) | Full audit trail, recomputable, supports phased feature delivery |
| Service boundary | New module inside cmon-proxy | Reuses Router, auth, controller discovery; no new binary |
| Sampling interval | Hourly | Aligns with 24-hour billable threshold; ~8.7M rows/year at 1K nodes |
| Phase 1 audience | Severalnines billing (estate-wide) | Simpler scope; foundation for per-customer filtering later |
| Report immutability | Cryptographic sealing (SHA-256 + HMAC) | Tamper-evident reports for external sharing |
| Phase 1 delivery | API-only (JSON + CSV) | No frontend changes needed; UI follows in Phase 4 |

---

## Architecture Overview

```
cmon-proxy process
├── Router (existing)
│   ├── Sync() loop — discovers/manages controller clients
│   └── GetAllClusterInfo() — fetches & caches cluster+host data (60s TTL)
│
└── metering/ (new Go package)
    ├── MeteringCollector
    │   ├── hourly ticker
    │   ├── calls Router.GetAllClusterInfo(forceUpdate=true)
    │   ├── transforms response → []NodeSnapshot
    │   ├── diffs against previous snapshot (detect removed nodes)
    │   └── writes to StorageBackend
    │
    ├── ReportGenerator
    │   ├── aggregation queries (billable nodes, high-water marks, max concurrent)
    │   ├── report JSON assembly
    │   └── cryptographic sealing (SHA-256 + HMAC-SHA256)
    │
    ├── StorageBackend (interface)
    │   ├── SQLiteBackend (default)
    │   └── (future: PostgreSQLBackend)
    │
    └── API handlers (Gin routes under /v2/metering/)
```

---

## Data Model

### `node_snapshots` — raw hourly state (the event store)

```sql
CREATE TABLE node_snapshots (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    captured_at   TIMESTAMP NOT NULL,           -- when this snapshot was taken
    controller_id TEXT NOT NULL,                 -- controller URL or unique ID
    cluster_id    INTEGER NOT NULL,              -- CID
    cluster_name  TEXT NOT NULL,
    cluster_type  TEXT NOT NULL,                 -- "galera", "replication", "postgresql", etc.
    db_vendor     TEXT NOT NULL,                 -- "oracle", "percona", "mariadb", "community", etc.
    node_id       TEXT NOT NULL,                 -- "{controller_id}:{private_ip}" (stable identifier)
    hostname      TEXT NOT NULL,
    port          INTEGER NOT NULL,
    node_role     TEXT NOT NULL,                 -- "database", "proxysql" (eligible node types only)
    node_status   TEXT NOT NULL,                 -- "active", "stopped", "removed"
    vcpu          INTEGER,
    ram_mb        INTEGER,
    volume_gb     INTEGER,
    tags          TEXT                           -- JSON array of cluster tags (for Phase 3 filtering)
);

CREATE INDEX idx_snapshots_period  ON node_snapshots(captured_at, node_id);
CREATE INDEX idx_snapshots_node    ON node_snapshots(node_id, captured_at);
CREATE INDEX idx_snapshots_cluster ON node_snapshots(cluster_id, controller_id, captured_at);
```

Each hourly tick inserts one row per eligible node visible across all controllers. Append-only — rows are never updated or deleted (except by retention cleanup after 12 months).

### `billing_reports` — sealed period reports

```sql
CREATE TABLE billing_reports (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    report_version  INTEGER NOT NULL DEFAULT 1,  -- increments if regenerated
    period_start    TIMESTAMP NOT NULL,
    period_end      TIMESTAMP NOT NULL,
    generated_at    TIMESTAMP NOT NULL,
    report_data     TEXT NOT NULL,                -- full JSON report body
    sha256_hash     TEXT NOT NULL,                -- SHA-256 of report_data
    signature       TEXT,                         -- HMAC-SHA256 signature
    signing_key_id  TEXT,                         -- identifies which key signed it
    UNIQUE(period_start, period_end, report_version)
);
```

### `metering_config` — billing period and system settings

```sql
CREATE TABLE metering_config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
-- e.g. ("billing_period_months", "1"), ("min_active_hours", "24"), ("signing_key_id", "key-2026-01")
```

### Key Design Points

- **`node_id`** = `"{controller_id}:{private_ip}"` — unique across controllers (two controllers may manage overlapping private IP ranges)
- **`node_role`** filters to eligible nodes only: database nodes + ProxySQL
- **Tags** stored as JSON from Phase 1 — queried in Phase 3 without schema changes
- **High-water marks** (max vCPU, RAM, volume) are derived via `MAX()` over snapshot rows, not stored as mutable counters
- **Resource change timestamps** derived by comparing consecutive snapshots for a node
- **Stopped nodes:** A node that is stopped (from CC) but not removed from the cluster still appears in the `getAllClusterInfo` host list. It is recorded with `node_status = "stopped"`. Per the requirements, stopped nodes count toward billing until removed — the billable node query counts both `"active"` and `"stopped"` statuses toward the 24-hour threshold.
- **Vendor derivation:** The `db_vendor` is derived from the cluster's `vendor` field in the `getAllClusterInfo` response (which cc-cmon populates from the `server_node.properties` JSON). The collector maintains a mapping of `(cluster_type, vendor_string)` → normalized vendor name (e.g., `"Percona Server"` → `"percona"`, `"Oracle MySQL"` → `"oracle"`). Unknown vendors default to `"community"`.

---

## Collection Pipeline

### Hourly Collection Flow

1. `MeteringCollector` ticker fires every hour (aligned to hour boundaries)
2. Calls `Router.GetAllClusterInfo(forceUpdate=true)` — reuses existing parallel fan-out to N controllers
3. Iterates clusters → hosts, filters to **eligible nodes** (database + ProxySQL)
4. Builds `NodeSnapshot` structs with controller ID, cluster metadata, node specs, tags
5. **Diffs against previous snapshot** (kept in memory):
   - New nodes → insert with status `"active"`
   - Disappeared nodes → insert final row with status `"removed"`
   - Still present → insert with current status and resource values
6. Batch-inserts all snapshots in a single SQLite transaction

### Failure Handling

- **Controller unreachable:** Its nodes are absent from that snapshot (not marked removed). The 24-hour threshold naturally tolerates gaps.
- **Collector crash:** Next hourly tick picks up. Worst case: one hour of lost granularity.
- **`last_successful_collection`** timestamp in `metering_config` tracks health.

### Startup Behavior

1. Read last snapshot timestamp from DB
2. If >1 hour elapsed, immediately run a collection
3. Start hourly ticker aligned to next hour boundary

---

## Report Generation & Cryptographic Sealing

### Computation (all derived from raw snapshots)

**Billable node identification:**
```sql
SELECT node_id, COUNT(*) as active_hours
FROM node_snapshots
WHERE captured_at BETWEEN :period_start AND :period_end
  AND node_status IN ('active', 'stopped')  -- stopped nodes count until removed
  AND node_role IN ('database', 'proxysql')
GROUP BY node_id
HAVING COUNT(*) >= 24  -- billable threshold
```

**High-water marks per billable node:**
```sql
SELECT node_id, cluster_id, cluster_name, cluster_type, db_vendor, node_role,
       MAX(vcpu) as max_vcpu, MAX(ram_mb) as max_ram_mb, MAX(volume_gb) as max_volume_gb
FROM node_snapshots
WHERE captured_at BETWEEN :period_start AND :period_end
  AND node_id IN (:billable_node_ids)
GROUP BY node_id
```

**Max concurrent nodes per cluster type + vendor:**
```sql
SELECT cluster_type, db_vendor, MAX(concurrent_count) as max_concurrent_nodes
FROM (
    SELECT captured_at, cluster_type, db_vendor,
           COUNT(DISTINCT node_id) as concurrent_count
    FROM node_snapshots
    WHERE captured_at BETWEEN :period_start AND :period_end
      AND node_id IN (:billable_node_ids)
      AND node_status = 'active'
    GROUP BY captured_at, cluster_type, db_vendor
)
GROUP BY cluster_type, db_vendor
```

**Resource change timestamps:**
```sql
-- When was max vCPU first observed?
SELECT node_id, MIN(captured_at) as max_vcpu_observed_at
FROM node_snapshots
WHERE node_id IN (:billable_node_ids)
  AND captured_at BETWEEN :period_start AND :period_end
  AND vcpu = (SELECT MAX(s2.vcpu) FROM node_snapshots s2
              WHERE s2.node_id = node_snapshots.node_id
              AND s2.captured_at BETWEEN :period_start AND :period_end)
GROUP BY node_id
```

### Report JSON Structure

```json
{
  "report_version": 1,
  "period_start": "2026-04-01T00:00:00Z",
  "period_end": "2026-04-30T23:59:59Z",
  "generated_at": "2026-05-01T00:05:00Z",
  "summary": {
    "total_billable_nodes": 47,
    "grand_total_max_vcpu": 192,
    "grand_total_max_ram_gb": 384,
    "grand_total_max_volume_gb": 4800
  },
  "by_type_and_vendor": [
    {
      "cluster_type": "galera",
      "db_vendor": "percona",
      "max_concurrent_nodes": 12,
      "max_vcpu": 48,
      "max_ram_gb": 96,
      "max_volume_gb": 1200
    }
  ],
  "node_details": [
    {
      "node_id": "ctrl-1:10.0.1.5",
      "cluster_id": 3,
      "cluster_name": "prod-galera-01",
      "cluster_type": "galera",
      "db_vendor": "percona",
      "node_role": "database",
      "active_hours": 720,
      "max_vcpu": 8,
      "max_vcpu_observed_at": "2026-04-15T10:00:00Z",
      "max_ram_mb": 16384,
      "max_ram_observed_at": "2026-04-15T10:00:00Z",
      "max_volume_gb": 200,
      "max_volume_observed_at": "2026-04-01T00:00:00Z",
      "resource_changes": [
        {"at": "2026-04-15T10:00:00Z", "field": "vcpu", "from": 4, "to": 8},
        {"at": "2026-04-20T14:00:00Z", "field": "vcpu", "from": 8, "to": 4}
      ]
    }
  ]
}
```

### Cryptographic Sealing

1. **Canonicalize** — serialize `report_data` with sorted keys, no whitespace (deterministic JSON)
2. **Hash** — `SHA-256(report_data)` → stored as `sha256_hash`
3. **Sign** — `HMAC-SHA256(sha256_hash, signing_key)` → stored as `signature`
4. **Store** — insert into `billing_reports` with hash, signature, and `signing_key_id`

**Verification:** Recompute HMAC from stored `report_data`, compare to `signature`.

**Key rotation:** `signing_key_id` field means old reports stay verifiable with their original key.

**Re-generation:** `report_version` increments. Old versions retained for audit.

---

## API Endpoints

New Gin routes on cmon-proxy under `/v2/metering/`. All require admin auth via existing middleware.

### `POST /v2/metering/reports`

| Operation | Description |
|---|---|
| `generateReport` | Compute and seal a billing report for a given period. Params: `period_start`, `period_end`, `format` ("json"/"csv"). Idempotent — returns cached sealed report if one exists. Pass `force_regenerate: true` to create a new version. |
| `listReports` | List metadata for all sealed reports (id, period, generated_at, hash, total nodes). |
| `verifyReport` | Recompute hash + signature for a given `report_id`, return whether they match. |
| `exportReport` | Return a report in the requested `format`. CSV produces a ZIP with `summary.csv` + `node_details.csv`. |

### `POST /v2/metering/status`

| Operation | Description |
|---|---|
| `getMeteringStatus` | Collector health: last collection time, snapshot count, DB size, current period stats. |

### Design Notes

- Follows existing cmon-proxy RPC convention (`POST` with `operation` field)
- `generateReport` is idempotent for same period — safe to retry
- CSV column structure matches the requirements doc table format

---

## Phased Delivery

### Phase 1: Foundation — Data Collection & Storage

**Scope:**
- `StorageBackend` interface + SQLite adapter
- `MeteringCollector` goroutine (hourly ticker, snapshot capture, node diff logic)
- Wire into cmon-proxy startup/shutdown lifecycle
- `getMeteringStatus` endpoint
- Configuration: enable/disable metering, SQLite DB path, sampling interval

**Test plan:**
- Start cmon-proxy with metering enabled against a test controller
- Verify snapshots appear in SQLite after several hours
- Add/remove a node from a cluster, confirm diff detection works
- Confirm status endpoint returns correct collector state
- Kill and restart cmon-proxy, verify it catches up on missed snapshots

**Key files to modify:**
- `cmon-proxy/multi/proxy.go` — start/stop collector in proxy lifecycle
- `cmon-proxy/multi/router/router.go` — collector reads from Router
- New: `cmon-proxy/metering/` package (collector.go, storage.go, sqlite.go, models.go)
- New: `cmon-proxy/metering/api/` (status handler)

---

### Phase 2: Report Generation — Estate-Wide Severalnines Billing

**Scope:**
- Billing period computation (configurable period length)
- Aggregation queries (billable node filtering, high-water marks, max concurrent)
- Report JSON assembly
- Cryptographic sealing (SHA-256 + HMAC-SHA256)
- `generateReport`, `listReports`, `verifyReport`, `exportReport` endpoints
- CSV export

**Test plan:**
- Run against Phase 1 data that's been collecting for ≥1 billing period
- Generate a report, manually spot-check numbers against raw snapshots
- Verify the seal; tamper with report JSON; confirm verification fails
- Export CSV, confirm it matches the requirements doc table format
- Regenerate a report, confirm version increments and old version is retained
- Test edge cases: nodes active exactly 24 hours, nodes at 23 hours (excluded), resource changes mid-period

**Key files to modify:**
- New: `cmon-proxy/metering/report.go` (aggregation + report assembly)
- New: `cmon-proxy/metering/sealing.go` (crypto sealing + verification)
- New: `cmon-proxy/metering/api/reports.go` (report endpoints)
- Extend: `cmon-proxy/metering/storage.go` (report storage methods)

---

### Phase 3: Customer-Level Filtering — MSP/CSP Billing

**Scope:**
- Filter parameters on `generateReport`: `tags`, `cluster_ids`, `cluster_names`
- Scoped aggregation queries
- Per-customer sealed reports
- Tag-based grouping in report output

**Test plan:**
- Create clusters with different tags representing different MSP customers
- Generate filtered reports, confirm each includes only relevant nodes
- Generate estate-wide report, confirm it equals sum of all customer reports
- Test overlapping tags, empty tag filters, nonexistent cluster IDs

**Key files to modify:**
- Extend: `cmon-proxy/metering/report.go` (add filter params to queries)
- Extend: `cmon-proxy/metering/api/reports.go` (accept filter params)

---

### Phase 4: UI & Integrations

**Scope:**
- Reports page in cc-monorepo (browse/export billing reports)
- Webhook/callback on report generation
- Optional PostgreSQL storage backend

**Test plan:**
- Use UI to browse reports, export CSV
- Configure webhook, confirm it fires on report generation
- Test PostgreSQL backend with same data, compare report output to SQLite

**Key files to modify:**
- New: `cc-monorepo/` — reports page component
- New: `cmon-proxy/metering/postgres.go`
- Extend: `cmon-proxy/metering/collector.go` (webhook notification)

---

## Flexibility Matrix

| Decision | Locked in | Changeable later |
|---|---|---|
| Hourly snapshot granularity | Phase 1 | Can add sub-hourly later (more rows) |
| SQLite as default storage | Phase 1 | Swappable via StorageBackend interface |
| Node ID = `controller_id:private_ip` | Phase 1 | Requires migration — choose carefully |
| Report JSON structure | Phase 2 | Versioned — new versions can change structure |
| Sealing algorithm (HMAC-SHA256) | Phase 2 | `signing_key_id` supports algorithm rotation |
| Tag-based filtering | Phase 3 | Tags stored from Phase 1, just not queried yet |

**Architectural invariant:** Raw snapshots are the source of truth; everything else is derived. Any phase can be reworked without data loss.

---

## Data Retention

- **Raw snapshots:** Retained for 12 months. A daily cleanup job (goroutine on a 24-hour ticker) deletes rows from `node_snapshots` where `captured_at < now - 12 months`. Runs at a configurable time (default: 03:00 UTC) to avoid overlap with collection or report generation.
- **Sealed reports:** Never deleted. Reports are small (JSON blobs) and must remain available for audit indefinitely.
- **Retention period** is configurable via `metering_config` key `retention_months` (default: 12).

---

## Verification Plan (End-to-End)

1. **Phase 1 soak test:** Run collector for 48+ hours against a multi-controller setup with 5+ clusters. Verify snapshot counts, node detection, and resource value capture.
2. **Phase 2 report accuracy:** Manually compute expected values from raw SQLite data. Compare to generated report. Test boundary conditions (exactly 24h active, period boundaries, resource changes).
3. **Phase 2 seal integrity:** Generate report → verify passes → modify one byte of report_data → verify fails.
4. **Phase 3 filter correctness:** Sum of filtered reports must equal estate-wide report for same period.
5. **Retention:** Verify snapshots older than 12 months are cleaned up. Verify sealed reports are never cleaned up.
