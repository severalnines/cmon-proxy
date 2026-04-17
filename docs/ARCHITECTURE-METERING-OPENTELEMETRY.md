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

## OTel Metrics Schema

### Resource Attributes (per cmon-proxy instance)

| Attribute | Example | Description |
|---|---|---|
| `service.name` | `cmon-proxy` | OTel standard service identifier |
| `service.instance.id` | `proxy-01` | Distinguishes multi-proxy setups |
| `controller.id` | `https://ctrl-1:9501` | CMON controller URL or xid |

### Metrics Emitted

| Metric Name | Type | Unit | Description |
|---|---|---|---|
| `cc.node.active` | Gauge (1/0) | — | 1 if node is present in cluster (active or stopped). Stopped nodes count as active for billing. 0 if absent/removed. |
| `cc.node.cpu.count` | Gauge | `{cores}` | vCPU count (from getMeteringData ncpus) |
| `cc.node.memory.total` | Gauge | `MiBy` | Total RAM in MB |
| `cc.node.disk.total` | Gauge | `MiBy` | Largest disk mount in MB |

### Data-Point Attributes (per metric data point)

| Attribute | Example | Description |
|---|---|---|
| `cc.cluster.id` | `1` | Cluster ID within the controller |
| `cc.cluster.name` | `prod-galera` | Human-readable cluster name |
| `cc.cluster.type` | `GALERA` | Cluster type |
| `cc.db.vendor` | `percona` | Normalized vendor name |
| `cc.node.id` | `ctrl-1:10.0.1.1` | Stable node identifier |
| `cc.node.hostname` | `db-node-1` | Hostname |
| `cc.node.port` | `3306` | Service port |
| `cc.node.role` | `database` | `database` or `proxysql` |
| `cc.node.class` | `CmonGaleraHost` | CMON host class name |
| `cc.node.status` | `CmonHostOnline` | Raw CMON host status |
| `cc.cluster.tags` | `["customer-123"]` | JSON array of cluster tags |

## Data Flow

### Emission (cmon-proxy, periodic)

```
Router.GetMeteringData(forceUpdate=true)
  → For each cluster → For each eligible host:
    Emit cc.node.active = 1
    Emit cc.node.cpu.count = ncpus
    Emit cc.node.memory.total = total_memory_mb
    Emit cc.node.disk.total = total_disk_mb
    (all with cc.* attributes)
  → OTLP gRPC push to cmon-telemetry
```

### Reception (cmon-telemetry)

```
OTLP ExportMetricsServiceRequest received
  → For each data point on cc.node.active:
    Extract cc.* attributes → NodeSnapshot
    value == 1 → status "active" or "stopped" (from cc.node.status)
    value == 0 → status "removed"
    Read structured body fields (vcpu, memory, disk) from the same LogRecord
  → Lifecycle tracker: diff against previous tick → detect removals
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
| `internal/receiver/otlp.go` | OTLP gRPC server, metric → snapshot conversion |
| `internal/metering/` | Models, storage, SQLite, report, sealing (reused from cmon-proxy v1) |
| `internal/lifecycle/tracker.go` | Node diff detection (removed node tracking) |
| `internal/api/server.go` | Gin REST API (reports, status) |

## Deduplication (multi-proxy)

When N proxies manage overlapping controllers, cmon-telemetry deduplicates by `cc.node.id` per collection tick. The `service.instance.id` tracks which proxy reported it but doesn't create duplicate billing entries.

## Package Structure

```
cc-telemetry/                        # New repo
├── cmd/cmon-telemetry/main.go       # Binary entry point
├── internal/
│   ├── receiver/otlp.go             # OTLP gRPC receiver
│   ├── metering/                    # Reused from cmon-proxy v1
│   │   ├── models.go
│   │   ├── storage.go
│   │   ├── sqlite.go
│   │   ├── report.go
│   │   ├── sealing.go
│   │   └── status.go
│   ├── lifecycle/tracker.go         # Node add/remove detection
│   └── api/server.go                # REST API
├── etc/
│   ├── systemd/system/cmon-telemetry.service
│   └── cmon-telemetry/config.yaml   # Default config
├── Makefile
├── go.mod
└── CMakeLists.txt                   # DEB/RPM packaging
```
