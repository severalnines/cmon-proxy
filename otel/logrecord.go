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
	"time"

	"github.com/severalnines/cmon-proxy/cmon/api"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
)

// buildNodeLogRecord constructs one OTLP LogRecord describing an eligible
// node snapshot. The record's body is a typed KvList holding the variable
// fields; attributes carry the identity keys used for downstream filtering.
func buildNodeLogRecord(nodeID, controllerID string, cluster *api.Cluster, host *api.Host, className string, hw *HostHardwareStats) *logspb.LogRecord {
	now := uint64(time.Now().UnixNano())

	body := []*commonpb.KeyValue{
		strAttr("node_id", nodeID),
		strAttr("hostname", host.Hostname),
		intAttr("port", int64(host.Port)),
		strAttr("node_role", NodeRoleFromClassName(className)),
		strAttr("node_class", className),
		strAttr("node_status", host.HostStatus),
	}
	if hw != nil {
		if hw.RAMMB != nil {
			body = append(body, intAttr("ram_mb", int64(*hw.RAMMB)))
		}
		if hw.VolumeGB != nil {
			body = append(body, intAttr("volume_gb", int64(*hw.VolumeGB)))
		}
	}
	if len(cluster.Tags) > 0 {
		body = append(body, stringArrayAttr("tags", cluster.Tags))
	}

	attrs := []*commonpb.KeyValue{
		strAttr("cc.controller.id", controllerID),
		intAttr("cc.cluster.id", int64(cluster.ClusterID)),
		strAttr("cc.cluster.name", cluster.ClusterName),
		strAttr("cc.cluster.type", cluster.ClusterType),
		strAttr("cc.db.vendor", NormalizeVendor(cluster.Vendor)),
	}

	return &logspb.LogRecord{
		TimeUnixNano:         now,
		ObservedTimeUnixNano: now,
		SeverityNumber:       logspb.SeverityNumber_SEVERITY_NUMBER_INFO,
		SeverityText:         "INFO",
		Body: &commonpb.AnyValue{Value: &commonpb.AnyValue_KvlistValue{
			KvlistValue: &commonpb.KeyValueList{Values: body},
		}},
		Attributes: attrs,
	}
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

func stringArrayAttr(key string, values []string) *commonpb.KeyValue {
	arr := make([]*commonpb.AnyValue, len(values))
	for i, v := range values {
		arr[i] = &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: v}}
	}
	return &commonpb.KeyValue{
		Key: key,
		Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_ArrayValue{
			ArrayValue: &commonpb.ArrayValue{Values: arr},
		}},
	}
}
