#!/bin/bash
# Start cmon-proxy with the OTel metering emitter for soak testing.
#
# Usage: ./scripts/start-soak-emitter.sh [interval] [endpoint]
#   interval  - emission interval (default: 10m)
#   endpoint  - cmon-telemetry gRPC address (default: localhost:4317)
#
# Prerequisites:
#   - A ccmgr.yaml in the current directory (or --basedir) with at least
#     one CMON controller configured
#   - cmon-telemetry running and listening on the endpoint

set -e

INTERVAL="${1:-10m}"
ENDPOINT="${2:-localhost:4317}"

export OTEL_METERING_ENABLED=true
export OTEL_METERING_ENDPOINT="$ENDPOINT"
export OTEL_METERING_INTERVAL="$INTERVAL"
export OTEL_METERING_INSECURE=true
export OTEL_METERING_INSTANCE="soak-proxy-$(hostname -s)"

echo "=== Starting cmon-proxy (soak OTel emitter mode) ==="
echo "Endpoint:  $ENDPOINT"
echo "Interval:  $INTERVAL"
echo "Instance:  $OTEL_METERING_INSTANCE"
echo ""
echo "Press Ctrl+C to stop."
echo ""

# Build and run.
cd "$(dirname "$0")/.."
go build -o build/ccmgr .
exec ./build/ccmgr --basedir=.
