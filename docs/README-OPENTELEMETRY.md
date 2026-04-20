# Usage Metering v2 — OpenTelemetry Operator Guide

## Overview

ClusterControl usage metering v2 uses OpenTelemetry to decouple data collection from billing. cmon-proxy emits OTel log records about managed database nodes. A separate service, cmon-telemetry, receives these records and generates sealed billing reports.

## Components

| Component | Package | Purpose |
|---|---|---|
| cmon-proxy | `clustercontrol-proxy` | Emits OTel log records about cluster/node state |
| cmon-telemetry | `clustercontrol-telemetry` | Receives logs, stores snapshots, generates reports |

## Quick Start

### 1. Install cmon-telemetry

```bash
# DEB
apt install clustercontrol-telemetry

# RPM
yum install clustercontrol-telemetry
```

### 2. Configure cmon-telemetry

Edit `/etc/cmon-telemetry/config.yaml`:

```yaml
otlp_listen: ":4317"
db_path: /var/lib/cmon-telemetry/metering.db
collection_interval: "60m"
billing_period_months: 1
min_active_hours: 24
retention_months: 12
api_listen: ":9520"

# Generate with: openssl rand -hex 32
signing_key: "your-256-bit-hex-key"
key_id: "key-2026-Q2"
```

Start the service:

```bash
systemctl enable cmon-telemetry
systemctl start cmon-telemetry
```

### 3. Enable the OTel emitter in cmon-proxy

Edit `/etc/default/cmon-proxy.env`:

```bash
OTEL_METERING_ENABLED=true
OTEL_METERING_ENDPOINT=localhost:4317
OTEL_METERING_INTERVAL=60m
```

Or in `ccmgr.yaml`:

```yaml
otel_metering_enabled: true
otel_metering_endpoint: "localhost:4317"
otel_metering_interval: "60m"
otel_metering_insecure: true
```

Restart cmon-proxy:

```bash
systemctl restart cmon-proxy
```

### 4. Verify data is flowing

```bash
# Check cmon-telemetry status
curl -s http://localhost:9520/status | python3 -m json.tool
```

```json
{
  "receiver_running": true,
  "last_received": "2026-04-16T15:00:00Z",
  "total_snapshots": 220,
  "db_size_bytes": 45056,
  "connected_emitters": 1
}
```

### 5. Generate a billing report

```bash
curl -s -X POST http://localhost:9520/reports \
  -H 'Content-Type: application/json' \
  -d '{
    "operation": "generateReport",
    "period_start": "2026-04-01T00:00:00Z",
    "period_end": "2026-04-30T23:59:59Z"
  }' | python3 -m json.tool
```

#### Per-customer / per-tenant reports

`generateReport` also accepts optional filters so MSPs and CSPs can produce a
sealed report restricted to a single customer or tenant. Filters are combined
with AND across fields; values inside each list combine with OR. A snapshot's
`cc.cluster.tags` attribute is matched against `tags`.

| Field | Type | Semantics |
|---|---|---|
| `tags` | `[]string` | Match snapshots whose tag list contains any of the listed values |
| `cluster_ids` | `[]uint64` | Match snapshots whose `cluster_id` is in the list |
| `cluster_names` | `[]string` | Match snapshots whose `cluster_name` is in the list |

```bash
# Billing report for a single tenant (tag)
curl -s -X POST http://localhost:9520/reports \
  -H 'Content-Type: application/json' \
  -d '{
    "operation": "generateReport",
    "period_start": "2026-04-01T00:00:00Z",
    "period_end":   "2026-04-30T23:59:59Z",
    "tags": ["customer-acme"]
  }' | python3 -m json.tool
```

Filtered reports are sealed and stored as their own entries in
`billing_reports`, independently verifiable via `verifyReport`. The returned
payload includes a top-level `"filter"` object describing the scope it covers.
Unlike estate-wide reports, filtered generations always create a new sealed
version (they are not served from the period cache).

## Configuration Reference

### cmon-telemetry (`/etc/cmon-telemetry/config.yaml`)

| Key | Default | Description |
|---|---|---|
| `otlp_listen` | `:4317` | OTLP gRPC listen address |
| `db_path` | `/var/lib/cmon-telemetry/metering.db` | SQLite database path (or `postgres://` DSN) |
| `collection_interval` | `60m` | Expected snapshot cadence from cmon-proxy, used for billing duration and health checks |
| `billing_period_months` | `1` | Billing period in calendar months |
| `min_active_hours` | `24` | Minimum hours for a node to be billable |
| `retention_months` | `12` | Snapshot retention period |
| `signing_key` | (none) | HMAC-SHA256 signing key for report sealing |
| `key_id` | `default` | Signing key identifier |
| `verification_keys` | (none) | Map of historical key IDs → keys for verification |
| `api_listen` | `:9520` | REST API listen address |

### cmon-proxy OTel emitter

| Env Variable | YAML Key | Default | Description |
|---|---|---|---|
| `OTEL_METERING_ENABLED` | `otel_metering_enabled` | `false` | Enable OTel metering emission |
| `OTEL_METERING_ENDPOINT` | `otel_metering_endpoint` | `localhost:4317` | cmon-telemetry gRPC address |
| `OTEL_METERING_INTERVAL` | `otel_metering_interval` | `60m` | Collection/emission interval |
| `OTEL_METERING_INSECURE` | `otel_metering_insecure` | `true` | Skip TLS for gRPC connection |
| — | `otel_metering_tls_cert` | (none) | Client TLS certificate path |
| — | `otel_metering_tls_key` | (none) | Client TLS private key path |
| — | `otel_metering_tls_ca` | (none) | CA certificate for server verification |

## gRPC TLS Setup

By default, the connection between cmon-proxy and cmon-telemetry is insecure (plaintext). For production, enable TLS or mTLS.

### Generate certificates

```bash
# 1. Create a CA (one-time, shared between both services)
openssl req -x509 -newkey rsa:4096 -keyout ca.key -out ca.crt -days 3650 -nodes \
  -subj "/CN=cmon-telemetry-ca"

# 2. Server cert (for cmon-telemetry)
openssl req -newkey rsa:4096 -keyout server.key -out server.csr -nodes \
  -subj "/CN=cmon-telemetry"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 365 \
  -extfile <(printf "subjectAltName=DNS:localhost,DNS:cmon-telemetry,IP:127.0.0.1")

# 3. Client cert (for cmon-proxy — only needed for mTLS)
openssl req -newkey rsa:4096 -keyout client.key -out client.csr -nodes \
  -subj "/CN=cmon-proxy"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out client.crt -days 365
```

### Configure cmon-telemetry (server side)

In `/etc/cmon-telemetry/config.yaml`:

```yaml
# TLS (server authenticates to clients)
otlp_tls_cert: /etc/cmon-telemetry/server.crt
otlp_tls_key: /etc/cmon-telemetry/server.key

# mTLS (also verify client certs — add this line)
otlp_tls_ca: /etc/cmon-telemetry/ca.crt
```

### Configure cmon-proxy (client side)

In `ccmgr.yaml`:

```yaml
otel_metering_insecure: false  # disable plaintext

# TLS (verify server using CA)
otel_metering_tls_ca: /etc/cmon-proxy/ca.crt

# mTLS (also present client cert)
otel_metering_tls_cert: /etc/cmon-proxy/client.crt
otel_metering_tls_key: /etc/cmon-proxy/client.key
```

### TLS modes

| Mode | cmon-telemetry config | cmon-proxy config |
|---|---|---|
| Plaintext | (none) | `otel_metering_insecure: true` |
| TLS (server auth) | cert + key | `otel_metering_tls_ca` |
| mTLS (mutual) | cert + key + ca | cert + key + ca |

## REST API (cmon-telemetry :9520)

### GET /status

Returns receiver health, snapshot count, and database size.

### POST /reports

| Operation | Description |
|---|---|
| `generateReport` | Compute and seal a billing report. Params: optional `period_start`, `period_end`. When omitted, the most recently completed configured billing period is used. `force_regenerate: true` creates a new version. |
| `listReports` | Return metadata for all sealed reports. |
| `verifyReport` | Recompute hash + signature for a `report_id`. |
| `exportReport` | Download as JSON or CSV (ZIP with summary + node_details). |

## Multi-Proxy HA Topology

```
cmon-proxy-1 (site A) ──┐
cmon-proxy-2 (site B) ──┤── OTLP gRPC ──► cmon-telemetry (central)
cmon-proxy-3 (site C) ──┘                      │
                                               ├── SQLite/PostgreSQL
                                               └── REST API :9520
```

Each proxy emits independently. cmon-telemetry enforces a `UNIQUE(captured_at, node_id)` constraint on its event store and uses an in-memory FIFO of recently-flushed ticks in the ingestion pipeline, so two proxies reporting the same controller at the same tick — or a single proxy retrying a batch after a restart — produce exactly one row per (tick, node). See `cc-telemetry/ARCHITECTURE.md` → "Snapshot Deduplication".

## OTel Logs Emitted

cmon-proxy emits one OTLP **LogRecord** per eligible node on each collection tick. A node snapshot is a structured state record (identity, role, hardware high-water marks, tags) — it is carried on the OTLP logs signal, not the metrics signal, because it describes an event with structured body rather than a time-series measurement.

Each record is self-contained; the receiver decodes it 1:1 into a `NodeSnapshot` with no cross-record correlation.

### Record identity — attributes

The LogRecord's `attributes` carry the identity and query keys suited to downstream indexing (Loki label selectors, Elasticsearch keyword fields):

| Attribute | Type | Description |
|---|---|---|
| `cc.controller.id` | string | CMON controller XID |
| `cc.cluster.id` | int | Cluster ID |
| `cc.cluster.name` | string | Cluster display name |
| `cc.cluster.type` | string | Deployment type (e.g. `GALERA`, `POSTGRESQL_SINGLE`) |
| `cc.db.vendor` | string | Normalized vendor (`percona`, `mariadb`, `mongodb`, …) |

The Resource carries `service.name = cmon-proxy` and `service.instance.id`.

### Record payload — body (typed KvList)

The LogRecord's `body` is an OTLP KvList — a typed structured record (not an opaque JSON string), so downstream backends can index and query individual fields:

| Body field | Type | Description |
|---|---|---|
| `node_id` | string | `{controller_id}:{private_ip}` — stable across clouds |
| `hostname` | string | Node hostname |
| `port` | int | Service port |
| `node_role` | string | `database` or `proxysql` |
| `node_class` | string | CMON host class name |
| `node_status` | string | Raw CMON status; receiver normalises to `active` / `stopped` / `removed` |
| `vcpu` | int (optional) | vCPU count — see "vCPU recovery" below for the fetch chain |
| `ram_mb` | int (optional) | Total RAM in MB |
| `volume_gb` | int (optional) | Largest data volume in GB |
| `tags` | array of string (optional) | Cluster tag list (customer-id, tenant-id, …) |

Optional fields are absent from the body when unavailable rather than emitted as zero — downstream queries should check for presence.

### vCPU recovery

cmon-proxy fetches hardware stats in two stages:

1. **Primary: `getMeteringData`** (cc-cmon) returns per-host `ncpus`, `total_memory_mb`, and `largest_disk_mb` in one call, backed by the live stat collectors with a `CmonSheetManager` fallback on the controller side.
2. **vCPU recovery: `getCpuPhysicalInfo`.** If any host in the cluster still lacks `vcpu` after step 1, cmon-proxy calls `getCpuPhysicalInfo` and reconstructs vCPU by summing per-physical-CPU thread counts (`Siblings`, falling back to `CpuCores`) deduplicated by `PhysicalCPUID`. This closes the gap for hosts whose collectors haven't sampled CPU yet.

The `vcpu` field is only absent when both stages return nothing for that host. RAM and disk have no equivalent recovery path; they rely on the controller-side sheet-manager fallback.

## Fan-Out to Observability

The sealed billing report lives in cmon-telemetry. For log archival, search, and dashboards you can insert a standard OTel Collector between cmon-proxy and cmon-telemetry and fan out to log backends:

```
cmon-proxy ──► OTel Collector ──┬──► cmon-telemetry (billing)
                                ├──► Loki          (search + dashboards)
                                ├──► Elasticsearch (search + long-term)
                                └──► S3 / GCS      (archive)
```

### Minimal Collector config (Loki + S3 + cmon-telemetry)

```yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317

exporters:
  otlp/billing:
    endpoint: cmon-telemetry:4317
    tls:
      insecure: true

  loki:
    endpoint: http://loki:3100/loki/api/v1/push
    default_labels_enabled:
      exporter: false

  awss3:
    s3uploader:
      region: eu-west-1
      s3_bucket: clustercontrol-snapshots
      s3_prefix: cc-proxy/

service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [otlp/billing, loki, awss3]
```

This requires no changes to either cmon-proxy or cmon-telemetry.

> **History.** The emitter originally sent four OTel gauge metrics per node per tick; that was replaced by a single OTel LogRecord in CLUS-7333 (Phase 4). If you want metric-style aggregation on top of the Logs stream, the Collector's `logstometrics` processor can derive counts downstream — we don't ship that pipeline by default.

## Key Rotation

Same process as metering v1:

```bash
# Generate new key
openssl rand -hex 32

# Update config.yaml
signing_key: "<new-key>"
key_id: "key-2026-Q3"
verification_keys:
  key-2026-Q2: "<old-key>"
  key-2026-Q3: "<new-key>"

# Restart
systemctl restart cmon-telemetry
```

Old reports remain verifiable via `verification_keys`.

## Troubleshooting

**cmon-telemetry not receiving data:** Check `systemctl status cmon-telemetry` for listener errors. Verify `OTEL_METERING_ENDPOINT` in cmon-proxy matches `otlp_listen` in cmon-telemetry. Check firewall allows port 4317.

**Snapshots not appearing:** Verify cmon-proxy logs show `[otel-metering] emitted N node snapshots`. Check that the CMON controllers are reachable from cmon-proxy.

**Report shows 0 billable nodes:** Nodes need ≥24 cumulative hours (configurable via `min_active_hours`). Wait for enough collection ticks.

**vCPU missing for some nodes:** cmon-proxy fetches vCPU via `getMeteringData` and, as a fallback, `getCpuPhysicalInfo` (dedup by physical CPU id). If both return empty for a host — usually a newly-added node the controller hasn't sampled yet — the `vcpu` field is omitted and the report stores it as unknown until the next collection tick fills it in.
