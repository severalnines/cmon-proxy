# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Is

`cmon-proxy` (also known as `ccmgr`) is a Go reverse proxy and aggregator for multiple ClusterControl CMON instances. It exposes a unified RPC API (compatible with CMON v2) that aggregates cluster data, alarms, jobs, and backups across many CMON backend controllers. It also serves a separate web UI frontend.

The companion admin CLI binary is `ccmgradm` (in `./ccmgradm/`).

## Build Commands

```bash
# Standard Linux CI build (static, CGO disabled)
make ci

# Debug build (no optimizations, faster incremental)
make minimal-ci

# Build Docker image
make build

# Run in Docker with local data volume
make run

# Pull pre-built frontend files from Docker image
make getfrontendfiles

# Build DEB and RPM packages
make packages
```

Both commands output to `build/ccmgr` and `build/ccmgradm`.

For local macOS development, build directly with:
```bash
go build -o build/ccmgr .
go build -o build/ccmgradm ./ccmgradm
```

## Testing

```bash
# Run all tests
go test ./...

# Run tests with verbose output
go test -v ./...

# Run a single package's tests
go test -v ./multi/...

# Run a single test
go test -v -run TestName ./package/...
```

## Architecture

### Request Flow

```
HTTP Client
  → rpcserver (Gin, TLS)
    → Auth Middleware (session/JWT)
      → multi.Proxy handler
        → multi.Router (per-auth-context)
          → cmon.Client (one per CMON backend)
            → CMON v2 RPC API
```

### Key Packages

**`rpcserver/`** — HTTP server setup. Registers all API routes on a Gin router, manages TLS (self-signed or Let's Encrypt ACME), handles HTTPS redirects, serves static frontend files with dynamic CSP nonce injection, and applies middleware (auth, CORS, gzip, security headers).

**`multi/`** — Core business logic. `Proxy` is the top-level orchestrator that holds one or more `Router` instances (one default router for static users, one per LDAP user). `Router` maintains connections to all CMON backends and caches responses (60-second TTL) with parallel fetching. Handler files (`clusters.go`, `alarms.go`, `jobs.go`, `backups.go`, etc.) aggregate and paginate results across controllers.

**`cmon/`** — CMON backend client. `Client` manages an authenticated HTTP session to a single CMON instance using RSA-signed requests. Handles auto-reconnect on auth failure. `cmon/api/` contains all CMON RPC request/response type definitions.

**`auth/`** — Authentication middleware and providers. Three providers: `cmonproxy` (local users in YAML with PBKDF2 hashing), `cmon` (proxy credentials to a CMON backend), and `ldap` (direct LDAP authentication). JWT and cookie-based session management.

**`config/`** — Configuration loaded from `ccmgr.yaml`. Key structs: `Config`, `CmonInstance` (backend controllers), `ProxyUser` (local users), `WebServer` (TLS, CORS, security headers). The `Upgrade()` method handles config migrations. On first run, a default admin user is generated with a random password.

**`ccmgradm/`** — Admin CLI for managing users and controllers (add/update/drop user, add/update/drop controller, list controllers, init).

**`env/`** — Build-tag-based path resolution: `dev` tag uses relative paths, production uses `/usr/share/ccmgr/`.

**`otel/`** — OpenTelemetry metering emitter. Periodically collects per-cluster/per-host data via `getMeteringData` (primary) with `getCpuPhysicalInfo` vCPU recovery and a `statByName(memorystat/diskstat)` last-resort fallback, and pushes one OTLP LogRecord per eligible node per tick to cc-telemetry on `:4317`. See `docs/README-OPENTELEMETRY.md`.

### Authentication Model

- **Static/local users**: Credentials stored in `ccmgr.yaml`, managed via `ccmgradm`. All share the default `Router`.
- **LDAP users**: A dedicated `Router` is created per LDAP user at login time using their credentials to authenticate against CMON backends.
- **CMON-proxied users**: Can forward LDAP credentials to specific CMON instances.

### Multi-Controller Aggregation

Each CMON instance is an independent `cmon.Client`. The `Router` fetches data from all clients in parallel (default parallelism: 4), merges results, and caches them. Filtering, sorting, and pagination are applied at the proxy level after aggregation.

### Configuration File

The runtime config file is `ccmgr.yaml` (looked up from `--basedir`, defaulting to `.` in dev or `/etc/ccmgr/` in production). See `ccmgr.yaml.sample` for reference.
