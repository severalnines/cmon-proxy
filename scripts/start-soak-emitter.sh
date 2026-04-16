#!/bin/bash
# Start cmon-proxy with the OTel metering emitter for soak testing.
#
# Usage: ./scripts/start-soak-emitter.sh [interval] [endpoint]
#   interval  - emission interval (default: 10m)
#   endpoint  - cmon-telemetry gRPC address (default: localhost:4317)
#
# The script:
#   1. Sources .env for CMON_ENDPOINT, CMON_USERNAME, CMON_PASSWORD
#   2. Generates a temporary ccmgr.yaml from those credentials
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

# Generate a temporary ccmgr.yaml for the soak test.
# cmon-proxy loads {basedir}/ccmgr.yaml, so we write to /tmp/ccmgr-soak/ccmgr.yaml
SOAK_BASEDIR="/tmp/ccmgr-soak"
mkdir -p "$SOAK_BASEDIR"
SOAK_CONFIG="$SOAK_BASEDIR/ccmgr.yaml"
cat > "$SOAK_CONFIG" <<EOF
instances:
  - url: "$CMON_ENDPOINT"
    name: soak-controller
    username: "$CMON_USERNAME"
    password: "$CMON_PASSWORD"
timeout: 180
port: 19051
logfile: $SOAK_BASEDIR/ccmgr.log
EOF

echo "Generated soak config: $SOAK_CONFIG"
echo "  Controller: $CMON_ENDPOINT"
echo "  Username:   $CMON_USERNAME"
echo ""

# Set OTel emitter env vars.
export OTEL_METERING_ENABLED=true
export OTEL_METERING_ENDPOINT="$ENDPOINT"
export OTEL_METERING_INTERVAL="$INTERVAL"
export OTEL_METERING_INSECURE=true
export OTEL_METERING_INSTANCE="soak-proxy-$(hostname -s 2>/dev/null || echo local)"

echo "=== Starting cmon-proxy (soak OTel emitter mode) ==="
echo "CMON:      $CMON_ENDPOINT"
echo "OTel:      $ENDPOINT (interval=$INTERVAL)"
echo "Instance:  $OTEL_METERING_INSTANCE"
echo "Log:       $SOAK_BASEDIR/ccmgr.log"
echo ""
echo "Press Ctrl+C to stop."
echo ""

# Build and run with the generated config.
go build -o build/ccmgr .
exec ./build/ccmgr --basedir="$SOAK_BASEDIR"
