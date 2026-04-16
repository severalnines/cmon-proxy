# Usage Metering — Operator Guide

Usage metering tracks database node usage across ClusterControl for billing. It collects hourly snapshots of all eligible nodes and generates sealed billing reports.

## Quick Start

### 1. Enable metering

Edit `/etc/default/cmon-proxy.env`:

```bash
METERING_ENABLED=true
METERING_SIGNING_KEY=your-secret-signing-key
METERING_KEY_ID=key-2026-01
```

Restart the service:

```bash
systemctl restart cmon-proxy
```

### 2. Verify it's running

```bash
curl -sk -X POST https://localhost:19051/proxy/metering/status \
  -H 'Cookie: <session_cookie>' | python3 -m json.tool
```

```json
{
  "collector_running": true,
  "last_successful_collection": "2026-04-16T12:00:00Z",
  "total_snapshots": 220,
  "oldest_snapshot": "2026-04-16T11:00:00Z",
  "db_size_bytes": 45056,
  "collection_interval": "1h0m0s"
}
```

### 3. Generate a billing report

```bash
curl -sk -X POST https://localhost:19051/proxy/metering/reports \
  -H 'Content-Type: application/json' \
  -H 'Cookie: <session_cookie>' \
  -d '{
    "operation": "generateReport",
    "period_start": "2026-04-01T00:00:00Z",
    "period_end": "2026-04-30T23:59:59Z"
  }' | python3 -m json.tool
```

## Configuration

All settings can be configured via environment variables in `/etc/default/cmon-proxy.env` (loaded by systemd) or in `ccmgr.yaml`. Environment variables take precedence.

| Env Variable | YAML Key | Default | Description |
|---|---|---|---|
| `METERING_ENABLED` | `metering_enabled` | `false` | Enable/disable metering collection |
| `METERING_DB_PATH` | `metering_db_path` | `<basedir>/metering.db` | Path to the SQLite database |
| `METERING_INTERVAL` | `metering_interval` | `60m` | Collection interval (Go duration: `30m`, `1h`, `2h`) |
| `METERING_BILLING_PERIOD_MONTHS` | `metering_billing_period_months` | `1` | Billing period length in whole calendar months |
| `METERING_MIN_ACTIVE_HOURS` | `metering_min_active_hours` | `24` | Minimum cumulative active or stopped hours required for billing |
| `METERING_RETENTION_MONTHS` | `metering_retention_months` | `12` | Raw snapshot retention period in months |
| `METERING_SIGNING_KEY` | `metering_signing_key` | (none) | HMAC key for sealing reports |
| `METERING_KEY_ID` | `metering_key_id` | `default` | Identifier for the signing key (for rotation) |
| `METERING_VERIFICATION_KEYS` | `metering_verification_keys` | (none) | JSON object or YAML map of verification keys keyed by signing key ID |

**YAML example** (`ccmgr.yaml`):

```yaml
metering_enabled: true
metering_db_path: /var/lib/ccmgr/metering.db
metering_interval: "30m"
metering_billing_period_months: 1
metering_min_active_hours: 24
metering_retention_months: 12
metering_signing_key: "your-secret-key"
metering_key_id: "key-2026-01"
metering_verification_keys:
  key-2025-12: "previous-secret-key"
  key-2026-01: "your-secret-key"
```

## API Reference

All endpoints require authentication and are under `/proxy/metering/`.

### GET/POST `/proxy/metering/status`

Returns collector health and database statistics.

**Response:**

```json
{
  "collector_running": true,
  "collection_healthy": true,
  "health_status": "ok",
  "last_successful_collection": "2026-04-16T15:00:00Z",
  "total_snapshots": 4400,
  "oldest_snapshot": "2026-04-01T00:00:00Z",
  "db_size_bytes": 1048576,
  "collection_interval": "1h0m0s",
  "billing_period_months": 1,
  "min_active_hours": 24,
  "retention_months": 12,
  "last_retention_cleanup": "2026-04-16T00:00:00Z",
  "last_cleanup_deleted_rows": 24
}
```

### POST `/proxy/metering/reports`

All report operations use the `operation` field in the JSON body.

#### `generateReport`

Computes and seals a billing report for a given period. Idempotent — returns cached report if one already exists.

If `period_start` and `period_end` are omitted, cmon-proxy uses the most recently completed configured billing period. For example, with `metering_billing_period_months: 1`, a request made in April defaults to March 1 00:00:00 UTC through March 31 23:59:59 UTC.

**Request:**

```json
{
  "operation": "generateReport",
  "period_start": "2026-04-01T00:00:00Z",
  "period_end": "2026-04-30T23:59:59Z"
}
```

To regenerate (creates a new version):

```json
{
  "operation": "generateReport",
  "period_start": "2026-04-01T00:00:00Z",
  "period_end": "2026-04-30T23:59:59Z",
  "force_regenerate": true
}
```

**Response:**

```json
{
  "report_id": 1,
  "sealed": true,
  "report": {
    "report_version": 1,
    "period_start": "2026-04-01T00:00:00Z",
    "period_end": "2026-04-30T23:59:59Z",
    "generated_at": "2026-05-01T00:05:00Z",
    "summary": {
      "total_billable_nodes": 22,
      "grand_total_max_vcpu": 0,
      "grand_total_max_ram_gb": 40,
      "grand_total_max_volume_gb": 8800
    },
    "by_type_and_vendor": [
      {
        "cluster_type": "GALERA",
        "db_vendor": "percona",
        "max_concurrent_nodes": 3,
        "max_vcpu": 0,
        "max_ram_gb": 5,
        "max_volume_gb": 1200
      }
    ],
    "billing_table_rows": [
      {
        "row_type": "vendor",
        "deployment_type": "GALERA",
        "vendor": "percona",
        "max_concurrent_nodes": 3,
        "max_vcpu": 0,
        "max_ram_gb": 5,
        "max_volume_gb": 1200
      },
      {
        "row_type": "type_total",
        "deployment_type": "GALERA",
        "vendor": "Total",
        "max_concurrent_nodes": 3,
        "max_vcpu": 0,
        "max_ram_gb": 5,
        "max_volume_gb": 1200
      },
      {
        "row_type": "grand_total",
        "deployment_type": "",
        "vendor": "Grand Total",
        "max_concurrent_nodes": 22,
        "max_vcpu": 0,
        "max_ram_gb": 40,
        "max_volume_gb": 8800
      }
    ],
    "node_details": [
      {
        "node_id": "ctrl-1:10.0.1.1",
        "controller_id": "ctrl-1",
        "cluster_id": 1,
        "cluster_name": "prod-galera",
        "cluster_type": "GALERA",
        "db_vendor": "percona",
        "node_role": "database",
        "active_hours": 720,
        "max_vcpu": 0,
        "max_ram_mb": 1907,
        "max_ram_observed_at": "2026-04-01T00:00:00Z",
        "max_volume_gb": 409,
        "max_volume_observed_at": "2026-04-01T00:00:00Z",
        "resource_changes": []
      }
    ]
  }
}
```

#### `listReports`

Returns metadata for all sealed reports.

```json
{ "operation": "listReports" }
```

**Response:**

```json
{
  "reports": [
    {
      "id": 1,
      "report_version": 1,
      "period_start": "2026-04-01T00:00:00Z",
      "period_end": "2026-04-30T23:59:59Z",
      "generated_at": "2026-05-01T00:05:00Z",
      "sha256_hash": "a1b2c3...",
      "total_billable_nodes": 22
    }
  ]
}
```

#### `verifyReport`

Recomputes the SHA-256 hash and HMAC signature and compares to stored values.

```json
{ "operation": "verifyReport", "report_id": 1 }
```

**Response:**

```json
{
  "report_id": 1,
  "hash_valid": true,
  "signature_valid": true,
  "signing_key_id": "key-2026-01",
  "verification_key_found": true,
  "verified_at": "2026-05-10T12:00:00Z"
}
```

#### `exportReport`

Downloads a report as JSON or CSV.

```json
{ "operation": "exportReport", "report_id": 1, "format": "json" }
```

For CSV, returns a ZIP file containing `summary.csv` and `node_details.csv`. `summary.csv` is the billing-table export with vendor rows, per-deployment `Total` rows, and a `Grand Total` row:

```json
{ "operation": "exportReport", "report_id": 1, "format": "csv" }
```

## What Gets Metered

### Eligible nodes

Database hosts and ProxySQL nodes managed by ClusterControl:

- MySQL / MariaDB (replication, Galera, Group Replication)
- PostgreSQL / TimescaleDB
- MongoDB
- Redis / Valkey (Sentinel, Cluster)
- Elasticsearch
- SQL Server (MSSQL)
- ProxySQL

Excluded: controller nodes, Prometheus exporters, HAProxy, MaxScale, Keepalived.

### Billable threshold

A node is billable for a billing period if it has **24 or more cumulative hours** in "active" or "stopped" status by default. This threshold is configurable via `metering_min_active_hours`. Nodes that are stopped (from ClusterControl) still count until removed from the cluster.

### Tracked metrics per node

| Metric | Source | Notes |
|--------|--------|-------|
| Active hours | Snapshot count × configured interval | Reported as cumulative whole hours derived from the collection interval |
| Max vCPU | Not yet available | Requires CMON API enhancement |
| Max RAM (MB) | `memorystat` API → `ramtotal` | High-water mark per billing period |
| Max Volume (GB) | `diskstat` API → `total` | Largest disk mount, high-water mark |
| Resource changes | Consecutive snapshot diffs | Timestamps of increases/decreases |

### Report breakdown

Reports include:
- **Summary**: total billable nodes, sum of max resources
- **By type and vendor**: max concurrent nodes, max resources per cluster type + vendor
- **Node details**: per-node active hours, resource high-water marks, change history

## Data Retention

- **Snapshots**: retained for 12 months (configurable), then deleted by a daily cleanup job
- **Sealed reports**: never deleted — kept indefinitely for audit

## Running Integration Tests

The integration tests connect to a real CMON controller. Set environment variables and run:

```bash
source .env  # must define CMON_ENDPOINT, CMON_USERNAME, CMON_PASSWORD
go test -v -run TestIntegration ./metering/... -timeout 300s
```

Tests are automatically skipped if `CMON_ENDPOINT` is not set.

## Troubleshooting

**Metering not collecting**: Check `systemctl status cmon-proxy` logs for `[metering]` entries. Verify `METERING_ENABLED=true` in `/etc/default/cmon-proxy.env` and restart.

**RAM/volume nil in snapshots**: The stat API requires CMON's host collector to be active. Verify the controller is monitoring the hosts (check host status in ClusterControl UI).

**Report shows 0 billable nodes**: Nodes need at least `metering_min_active_hours` cumulative hours of "active" or "stopped" status in the billing period. Check if enough time has elapsed since metering was enabled.

**Signature verification fails**: Ensure the report's `signing_key_id` exists in `metering_verification_keys` or matches the current `METERING_KEY_ID`. After key rotation, keep old verification keys configured for old reports.
