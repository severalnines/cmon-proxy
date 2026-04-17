# Usage Metering v2 — OpenTelemetry Architecture

## Overview

Usage metering v2 splits the metering system into two components connected by OpenTelemetry:

1. **cmon-proxy** — thin OTel log emitter (collects cluster/host data, emits OTLP)
2. **cmon-telemetry** — standalone Go service (receives OTLP, stores snapshots, generates reports)

This replaces the embedded metering module (v1) which tightly coupled collection, storage, and reporting inside cmon-proxy.

### Why

- **OTel ecosystem** — structured snapshots can flow to Loki, Elasticsearch, or an OTel Collector alongside billing
- **Decoupled billing** — billing logic evolves independently with its own release cycle
- **Multi-proxy HA** — N cmon-proxy instances fan in to 1 cmon-telemetry via standard OTLP
- **Future direction** — aligns with ClusterControl's move toward OpenTelemetry

## System Architecture

```
cmon-proxy instance 1 ──┐
cmon-proxy instance 2 ──┤── OTLP gRPC :4317 ──► cmon-telemetry
cmon-proxy instance N ──┘                            │
                                                     ├── SQLite / PostgreSQL
                                                     └── REST API :9520
```

**cmon-proxy** periodically calls `getMeteringData` (or falls back to `getAllClusterInfo` + `statByName` for older controllers), maps the response to OTLP LogRecords, and pushes them over OTLP gRPC. No state, no storage — emit and forget.

**cmon-telemetry** receives OTLP log records, converts them to snapshot rows, tracks node lifecycle (detects added/removed nodes), stores in SQLite, generates sealed billing reports, and exposes a REST API.

The OTLP wire protocol means you can insert an OTel Collector between them for fan-out, or replace either side independently.

## OTel Logs Schema

### Resource Attributes (per cmon-proxy instance)

| Attribute | Example | Description |
|---|---|---|
| `service.name` | `cmon-proxy` | OTel standard service identifier |
| `service.instance.id` | `proxy-01` | Distinguishes multi-proxy setups |
| `cc.controller.id` | `ctrl-xid-1` | Stable controller identity attached per LogRecord |

### LogRecord Attributes (identity + query keys)

| Attribute | Example | Description |
|---|---|---|---|
| `cc.controller.id` | `ctrl-xid-1` | CMON controller xid |
| `cc.cluster.id` | `1` | Cluster ID within the controller |
| `cc.cluster.name` | `prod-galera` | Human-readable cluster name |
| `cc.cluster.type` | `GALERA` | Cluster type |
| `cc.db.vendor` | `percona` | Normalized vendor name |

### LogRecord Body (typed KvList payload)

| Field | Type | Description |
|---|---|---|
| `node_id` | string | `{controller_id}:{private_ip}` stable node identifier |
| `hostname` | string | Hostname |
| `port` | int | Service port |
| `node_role` | string | `database` or `proxysql` |
| `node_class` | string | CMON host class name |
| `node_status` | string | Raw CMON host status |
| `vcpu` | int (optional) | vCPU count from `getMeteringData.ncpus` |
| `ram_mb` | int (optional) | Total RAM in MB |
| `volume_gb` | int (optional) | Largest mount-point size in GB |
| `tags` | array of string (optional) | Cluster tag list |

## Data Flow

### Emission (cmon-proxy, periodic)

```
Router.GetMeteringData(forceUpdate=true)
  → For each cluster → For each eligible host:
    Build one OTLP LogRecord
    Attach cc.* identity attributes
    Populate body with node_id, status, vcpu, ram_mb, volume_gb, tags
  → OTLP gRPC push to cmon-telemetry
```

### Reception (cmon-telemetry)

```
OTLP ExportLogsServiceRequest received
  → For each LogRecord:
    Extract cc.* attributes → NodeSnapshot identity
    Decode body fields → status, vcpu, memory, disk, tags
  → Tick-bucketed ingestion dedupes same-node records per tick
  → Restart hydration + active-set diff emits synthetic "removed" snapshots
  → Batch-insert into SQLite
```

### Report Generation (cmon-telemetry, on-demand)

Same as v1: query snapshots for a billing period, identify billable nodes (≥24h active/stopped), compute high-water marks, max concurrency, seal with HMAC-SHA256. Exposed via REST API.

## Service Boundaries

### cmon-proxy changes

**Added:**
- `otel/` package: emitter goroutine + OTLP gRPC exporter (~200 lines)
- Config: `otel_metering_enabled`, `otel_metering_endpoint`, `otel_metering_interval`

**Removed (after cmon-telemetry is validated):**
- `metering/` package
- `rpcserver/metering.go`
- `/proxy/metering/*` REST endpoints
- Old metering config fields

### cmon-telemetry (new service)

| Component | Purpose |
|---|---|
| `cmd/cmon-telemetry/main.go` | Entry point, config, startup |
| `internal/receiver/otlp.go` | OTLP gRPC server, LogRecord → snapshot conversion |
| `internal/ingestion/pipeline.go` | Tick bucketing, dedupe, restart hydration, removed-node synthesis |
| `internal/metering/` | Models, storage, SQLite, report, sealing |
| `internal/api/server.go` | Gin REST API (reports, status) |

## Deduplication (multi-proxy)

When N proxies manage overlapping controllers, cmon-telemetry deduplicates by `cc.node.id` per collection tick. The `service.instance.id` tracks which proxy reported it but doesn't create duplicate billing entries.

## Package Structure

```
cc-telemetry/                        # New repo
├── cmd/cmon-telemetry/main.go       # Binary entry point
├── internal/
│   ├── receiver/otlp.go             # OTLP gRPC receiver
│   ├── ingestion/pipeline.go        # Tick bucketing + dedupe + lifecycle synthesis
│   ├── metering/
│   │   ├── models.go
│   │   ├── storage.go
│   │   ├── sqlite.go
│   │   ├── report.go
│   │   ├── sealing.go
│   │   └── status.go
│   └── api/server.go                # REST API
├── etc/
│   ├── systemd/system/cmon-telemetry.service
│   └── cmon-telemetry/config.yaml   # Default config
├── Makefile
├── go.mod
└── CMakeLists.txt                   # DEB/RPM packaging
```
