#!/bin/bash
# Start cmon-proxy with the OTel metering emitter for soak testing.
#
# Usage: ./scripts/start-soak-emitter.sh [interval] [endpoint]
#   interval  - emission interval (default: 10m)
#   endpoint  - cmon-telemetry gRPC address (default: localhost:4317)
#
# The script:
#   1. Sources .env for CMON_ENDPOINT, CMON_USERNAME, CMON_PASSWORD
#      (optional: CMON_ENDPOINT_2/_USERNAME_2/_PASSWORD_2 for a second
#      controller — enables multi-controller soak scenarios)
#   2. Generates a temporary ccmgr.yaml with 1 or 2 instances
#   3. Builds and starts cmon-proxy with the OTel emitter enabled
#
# Prerequisites:
#   - .env file in the repo root with CMON_ENDPOINT, CMON_USERNAME, CMON_PASSWORD
#   - cmon-telemetry running and listening on the endpoint

set -e

cd "$(dirname "$0")/.."
BASEDIR=$(pwd)

# Source .env if it exists.
if [ -f "$BASEDIR/.env" ]; then
    source "$BASEDIR/.env"
    echo "Loaded .env"
else
    echo "ERROR: No .env file found in $BASEDIR"
    echo "Create one with:"
    echo '  export CMON_ENDPOINT=https://your-controller:9501'
    echo '  export CMON_USERNAME=your-user'
    echo '  export CMON_PASSWORD=your-password'
    exit 1
fi

# Validate required vars.
if [ -z "$CMON_ENDPOINT" ] || [ -z "$CMON_USERNAME" ] || [ -z "$CMON_PASSWORD" ]; then
    echo "ERROR: .env must define CMON_ENDPOINT, CMON_USERNAME, and CMON_PASSWORD"
    exit 1
fi

INTERVAL="${1:-${INTERVAL:-10m}}"
ENDPOINT="${2:-${ENDPOINT:-localhost:4317}}"

# cmon-proxy loads {basedir}/ccmgr.yaml, so we write to /tmp/ccmgr-soak/ccmgr.yaml
SOAK_BASEDIR="/tmp/ccmgr-soak"
mkdir -p "$SOAK_BASEDIR"
SOAK_CONFIG="$SOAK_BASEDIR/ccmgr.yaml"

# Preserve xids across restarts. cmon-proxy mints a fresh xid per
# instance block the first time it reads the config, and the xid is
# what cc-telemetry keys snapshots by (cc.controller.id). If we
# overwrite the config on every start the xids rotate, which piles
# up stale-controller history in the DB and inflates estate-wide
# billable counts against a soak environment where the same
# physical controllers never actually changed.
#
# So: if the file already exists and references the expected CMON
# URLs, keep it untouched. Otherwise regenerate from scratch.
needs_regenerate() {
    [ ! -f "$SOAK_CONFIG" ] && return 0
    grep -qF "$CMON_ENDPOINT" "$SOAK_CONFIG" || return 0
    if [ -n "$CMON_ENDPOINT_2" ]; then
        grep -qF "$CMON_ENDPOINT_2" "$SOAK_CONFIG" || return 0
    fi
    return 1
}

if needs_regenerate; then
    # Primary controller block.
    cat > "$SOAK_CONFIG" <<EOF
instances:
  - url: "$CMON_ENDPOINT"
    name: soak-controller
    username: "$CMON_USERNAME"
    password: "$CMON_PASSWORD"
EOF

    # Optional second controller — append when CMON_ENDPOINT_2 is set.
    # Use a separate instance entry with name "soak-controller-2" so the
    # Billing UI's Controllers multi-select and the per-controller filter
    # (CLUS-7356) both have two distinct entries to work with.
    if [ -n "$CMON_ENDPOINT_2" ]; then
        : "${CMON_USERNAME_2:?CMON_ENDPOINT_2 is set but CMON_USERNAME_2 is missing}"
        : "${CMON_PASSWORD_2:?CMON_ENDPOINT_2 is set but CMON_PASSWORD_2 is missing}"
        cat >> "$SOAK_CONFIG" <<EOF
  - url: "$CMON_ENDPOINT_2"
    name: soak-controller-2
    username: "$CMON_USERNAME_2"
    password: "$CMON_PASSWORD_2"
EOF
    fi

    # Common tail.
    cat >> "$SOAK_CONFIG" <<EOF
timeout: 180
port: 19051
logfile: $SOAK_BASEDIR/ccmgr.log
EOF

    echo "Generated soak config: $SOAK_CONFIG"
else
    echo "Preserving existing soak config: $SOAK_CONFIG (xids stable across restart)"
fi
echo "  Controller: $CMON_ENDPOINT ($CMON_USERNAME)"
if [ -n "$CMON_ENDPOINT_2" ]; then
    echo "  Controller: $CMON_ENDPOINT_2 ($CMON_USERNAME_2)"
fi
echo ""

# Set OTel emitter env vars.
export OTEL_METERING_ENABLED=true
export OTEL_METERING_ENDPOINT="$ENDPOINT"
export OTEL_METERING_INTERVAL="$INTERVAL"
export OTEL_METERING_INSECURE=true
export OTEL_METERING_INSTANCE="soak-proxy-$(hostname -s 2>/dev/null || echo local)"

echo "=== Starting cmon-proxy (soak OTel emitter mode) ==="
echo "CMON:      $CMON_ENDPOINT"
if [ -n "$CMON_ENDPOINT_2" ]; then
    echo "CMON 2:    $CMON_ENDPOINT_2"
fi
echo "OTel:      $ENDPOINT (interval=$INTERVAL)"
echo "Instance:  $OTEL_METERING_INSTANCE"
echo "Log:       $SOAK_BASEDIR/ccmgr.log"
echo ""
echo "Press Ctrl+C to stop."
echo ""

# Build and run with the generated config.
go build -o build/ccmgr .
exec ./build/ccmgr --basedir="$SOAK_BASEDIR"
