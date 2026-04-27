package otel

// Copyright 2026 Severalnines AB
//
// This file is part of cmon-proxy.
//
// cmon-proxy is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 2 of the License.
//
// cmon-proxy is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with cmon-proxy. If not, see <https://www.gnu.org/licenses/>.

import (
	"context"
	"fmt"
	"sync"
	"time"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Emitter periodically collects metering data and emits OTel Logs via OTLP gRPC.
// One LogRecord per eligible node per tick; the record body carries the full
// node snapshot as a typed KvList (node_id, hostname, port, role, class,
// status, vcpu, ram_mb, volume_gb, tags), and attributes carry the identity
// keys (controller, cluster, vendor) suited to downstream querying.
type Emitter struct {
	provider   ClusterDataProvider
	endpoint   string
	interval   time.Duration
	instanceID string
	dialOpts   []grpc.DialOption
	logger     *zap.SugaredLogger
	stopCh     chan struct{}
	stopOnce   sync.Once
	done       chan struct{}
}

// NewEmitter creates a new OTLP Logs emitter.
// dialOpts configures the gRPC connection (insecure or TLS credentials).
func NewEmitter(provider ClusterDataProvider, endpoint string, interval time.Duration, instanceID string, dialOpts ...grpc.DialOption) *Emitter {
	if len(dialOpts) == 0 {
		dialOpts = []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	}
	return &Emitter{
		provider:   provider,
		endpoint:   endpoint,
		interval:   interval,
		instanceID: instanceID,
		dialOpts:   dialOpts,
		logger:     zap.L().Sugar(),
		stopCh:     make(chan struct{}),
		done:       make(chan struct{}),
	}
}

// Start begins the emission loop.
func (e *Emitter) Start() {
	go e.run()
}

// Stop signals the emitter to stop and waits for it to finish.
// Idempotent — calling Stop more than once is a no-op after the first call.
// Requires Start() to have been invoked; otherwise the wait on done blocks
// indefinitely (rpcserver guards this by only calling Stop when the emitter
// was successfully started).
func (e *Emitter) Stop() {
	e.stopOnce.Do(func() {
		close(e.stopCh)
	})
	<-e.done
}

func (e *Emitter) run() {
	defer close(e.done)

	// The Router authenticates asynchronously on startup. Retry the first
	// emission with backoff until we get data from at least one controller.
	e.logger.Info("[otel-metering] waiting for controllers to become available...")
	for attempt := 1; attempt <= 10; attempt++ {
		delay := time.Duration(attempt*5) * time.Second // 5s, 10s, 15s, ...
		select {
		case <-e.stopCh:
			return
		case <-time.After(delay):
		}

		controllerData := e.provider.FetchAllClusters()
		hasData := false
		for _, d := range controllerData {
			if d.Err == nil && len(d.Clusters) > 0 {
				hasData = true
				break
			}
		}

		if hasData {
			e.logger.Infof("[otel-metering] controllers ready after %ds", attempt*5)
			e.emitFromData(controllerData)
			break
		}

		e.logger.Infof("[otel-metering] no data yet (attempt %d/10), retrying in %s...", attempt, delay)
	}

	// Align to interval boundary.
	now := time.Now()
	next := now.Truncate(e.interval).Add(e.interval)
	alignTimer := time.NewTimer(next.Sub(now))
	defer alignTimer.Stop()

	select {
	case <-e.stopCh:
		return
	case <-alignTimer.C:
	}

	e.emit()

	ticker := time.NewTicker(e.interval)
	defer ticker.Stop()

	for {
		select {
		case <-e.stopCh:
			return
		case <-ticker.C:
			e.emit()
		}
	}
}

func (e *Emitter) emit() {
	e.logger.Info("[otel-metering] collecting data...")

	controllerData := e.provider.FetchAllClusters()
	e.emitFromData(controllerData)
}

func (e *Emitter) emitFromData(controllerData map[string]*ControllerClusters) {
	if len(controllerData) == 0 {
		e.logger.Warn("[otel-metering] no controllers returned data")
		return
	}

	var records []*logspb.LogRecord

	for addr, data := range controllerData {
		if data.Err != nil {
			e.logger.Warnf("[otel-metering] controller %s error: %v", addr, data.Err)
			continue
		}

		controllerID := data.ControllerID
		if controllerID == "" {
			// Defensive: the RouterAdapter already skips controllers with
			// an unsettled xid so we never reach here in production, but a
			// future provider implementation could regress. An empty
			// cc.controller.id would poison cc-telemetry's node_snapshots
			// keying — refuse to emit rather than leak an addr or a blank.
			e.logger.Warnf("[otel-metering] controller %s has empty ControllerID; skipping emit", addr)
			continue
		}

		for _, cluster := range data.Clusters {
			// Skip clusters where cmon returned empty identity fields. These
			// are transient missing-data states (controller restart,
			// mid-discovery, getMeteringData race) — not real classifications.
			// Emitting under the "" → "community" fallback poisons cc-telemetry's
			// append-only node_snapshots forever, which manifests in reports as
			// a phantom (cluster_type, "community") aggregation row alongside
			// the real (cluster_type, vendor) rows. Better to skip the tick;
			// the next one will recover.
			if cluster.ClusterType == "" {
				e.logger.Warnf("[otel-metering] controller %s cluster %d (%s) returned empty cluster_type; skipping this tick", controllerID, cluster.ClusterID, cluster.ClusterName)
				continue
			}
			if cluster.Vendor == "" {
				e.logger.Warnf("[otel-metering] controller %s cluster %d (%s, %s) returned empty vendor; skipping this tick", controllerID, cluster.ClusterID, cluster.ClusterName, cluster.ClusterType)
				continue
			}

			for _, host := range cluster.Hosts {
				if !IsEligibleHost(host) {
					continue
				}
				className := host.ClassName

				var hw *HostHardwareStats
				if data.HostStats != nil {
					hw = data.HostStats[host.HostID]
				}

				nodeID := fmt.Sprintf("%s:%s", controllerID, host.IP)
				records = append(records, buildNodeLogRecord(nodeID, controllerID, cluster, host, className, hw))
			}
		}
	}

	if len(records) == 0 {
		e.logger.Info("[otel-metering] no eligible nodes found")
		return
	}

	req := &collogspb.ExportLogsServiceRequest{
		ResourceLogs: []*logspb.ResourceLogs{{
			Resource: &resourcepb.Resource{
				Attributes: []*commonpb.KeyValue{
					strAttr("service.name", "cmon-proxy"),
					strAttr("service.instance.id", e.instanceID),
				},
			},
			ScopeLogs: []*logspb.ScopeLogs{{
				LogRecords: records,
			}},
		}},
	}

	if err := e.send(req); err != nil {
		e.logger.Errorf("[otel-metering] failed to send %d log records: %v", len(records), err)
		return
	}

	e.logger.Infof("[otel-metering] emitted %d node snapshots to %s", len(records), e.endpoint)
}

func (e *Emitter) send(req *collogspb.ExportLogsServiceRequest) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := grpc.NewClient(e.endpoint, e.dialOpts...)
	if err != nil {
		return fmt.Errorf("grpc connect: %w", err)
	}
	defer conn.Close()

	client := collogspb.NewLogsServiceClient(conn)
	_, err = client.Export(ctx, req)
	return err
}
