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
	"time"

	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Emitter periodically collects metering data and emits OTel metrics via OTLP gRPC.
type Emitter struct {
	provider   ClusterDataProvider
	endpoint   string
	interval   time.Duration
	instanceID string
	logger     *zap.SugaredLogger
	stopCh     chan struct{}
	done       chan struct{}
}

// NewEmitter creates a new OTel metrics emitter.
func NewEmitter(provider ClusterDataProvider, endpoint string, interval time.Duration, instanceID string) *Emitter {
	return &Emitter{
		provider:   provider,
		endpoint:   endpoint,
		interval:   interval,
		instanceID: instanceID,
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
func (e *Emitter) Stop() {
	close(e.stopCh)
	<-e.done
}

func (e *Emitter) run() {
	defer close(e.done)

	// Wait for the Router to authenticate with controllers before first emission.
	// The Router authenticates asynchronously on startup; 30 seconds is enough
	// for the initial auth + GetAllClusterInfo cache to populate.
	e.logger.Info("[otel-metering] waiting 30s for controller authentication...")
	select {
	case <-e.stopCh:
		return
	case <-time.After(30 * time.Second):
	}

	e.emit()

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
	if len(controllerData) == 0 {
		e.logger.Warn("[otel-metering] no controllers returned data")
		return
	}

	var allMetrics []*metricspb.Metric

	for addr, data := range controllerData {
		if data.Err != nil {
			e.logger.Warnf("[otel-metering] controller %s error: %v", addr, data.Err)
			continue
		}

		controllerID := data.ControllerID

		for _, cluster := range data.Clusters {
			for _, host := range cluster.Hosts {
				if host == nil || host.Nodetype == "controller" {
					continue
				}

				className := ""
				if host.WithClassName != nil {
					className = host.ClassName
				}

				if !IsEligibleNode(className) {
					continue
				}

				nodeID := fmt.Sprintf("%s:%s", controllerID, host.IP)
				now := uint64(time.Now().UnixNano())

				attrs := []*commonpb.KeyValue{
					strAttr("cc.node.id", nodeID),
					strAttr("cc.node.hostname", host.Hostname),
					intAttr("cc.cluster.id", int64(cluster.ClusterID)),
					strAttr("cc.cluster.name", cluster.ClusterName),
					strAttr("cc.cluster.type", cluster.ClusterType),
					strAttr("cc.db.vendor", NormalizeVendor(cluster.Vendor)),
					intAttr("cc.node.port", int64(host.Port)),
					strAttr("cc.node.role", NodeRoleFromClassName(className)),
					strAttr("cc.node.class", className),
					strAttr("cc.node.status", host.HostStatus),
				}

				if len(cluster.Tags) > 0 {
					// Encode tags as JSON string attribute.
					tagsStr := "["
					for i, tag := range cluster.Tags {
						if i > 0 {
							tagsStr += ","
						}
						tagsStr += `"` + tag + `"`
					}
					tagsStr += "]"
					attrs = append(attrs, strAttr("cc.cluster.tags", tagsStr))
				}

				// cc.node.active = 1 (node is present)
				allMetrics = append(allMetrics, gaugeMetric("cc.node.active", now, 1, attrs))

				// Hardware stats.
				var cpuCount, ramMB, diskMB int64
				if data.HostStats != nil {
					if hw, ok := data.HostStats[host.HostID]; ok && hw != nil {
						if hw.RAMMB != nil {
							ramMB = int64(*hw.RAMMB)
						}
						if hw.VolumeGB != nil {
							diskMB = int64(*hw.VolumeGB) // Note: field is VolumeGB but we pass raw value
						}
					}
				}
				allMetrics = append(allMetrics, gaugeMetric("cc.node.cpu.count", now, cpuCount, attrs))
				allMetrics = append(allMetrics, gaugeMetric("cc.node.memory.total", now, ramMB, attrs))
				allMetrics = append(allMetrics, gaugeMetric("cc.node.disk.total", now, diskMB, attrs))
			}
		}
	}

	if len(allMetrics) == 0 {
		e.logger.Info("[otel-metering] no eligible nodes found")
		return
	}

	// Build OTLP request.
	req := &colmetricspb.ExportMetricsServiceRequest{
		ResourceMetrics: []*metricspb.ResourceMetrics{{
			Resource: &resourcepb.Resource{
				Attributes: []*commonpb.KeyValue{
					strAttr("service.name", "cmon-proxy"),
					strAttr("service.instance.id", e.instanceID),
				},
			},
			ScopeMetrics: []*metricspb.ScopeMetrics{{
				Metrics: allMetrics,
			}},
		}},
	}

	// Send via gRPC.
	if err := e.send(req); err != nil {
		e.logger.Errorf("[otel-metering] failed to send %d metrics: %v", len(allMetrics)/4, err)
		return
	}

	e.logger.Infof("[otel-metering] emitted %d node metrics to %s", len(allMetrics)/4, e.endpoint)
}

func (e *Emitter) send(req *colmetricspb.ExportMetricsServiceRequest) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := grpc.NewClient(e.endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("grpc connect: %w", err)
	}
	defer conn.Close()

	client := colmetricspb.NewMetricsServiceClient(conn)
	_, err = client.Export(ctx, req)
	return err
}

func strAttr(key, value string) *commonpb.KeyValue {
	return &commonpb.KeyValue{
		Key:   key,
		Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: value}},
	}
}

func intAttr(key string, value int64) *commonpb.KeyValue {
	return &commonpb.KeyValue{
		Key:   key,
		Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: value}},
	}
}

func gaugeMetric(name string, timeNano uint64, value int64, attrs []*commonpb.KeyValue) *metricspb.Metric {
	return &metricspb.Metric{
		Name: name,
		Data: &metricspb.Metric_Gauge{
			Gauge: &metricspb.Gauge{
				DataPoints: []*metricspb.NumberDataPoint{{
					TimeUnixNano: timeNano,
					Value:        &metricspb.NumberDataPoint_AsInt{AsInt: value},
					Attributes:   attrs,
				}},
			},
		},
	}
}
