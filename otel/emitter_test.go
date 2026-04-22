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
	"net"
	"testing"
	"time"

	"github.com/severalnines/cmon-proxy/cmon/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

type capturingLogsServer struct {
	collogspb.UnimplementedLogsServiceServer
	requests []*collogspb.ExportLogsServiceRequest
}

func (s *capturingLogsServer) Export(_ context.Context, req *collogspb.ExportLogsServiceRequest) (*collogspb.ExportLogsServiceResponse, error) {
	s.requests = append(s.requests, req)
	return &collogspb.ExportLogsServiceResponse{}, nil
}

func intPtr(v int) *int { return &v }

func kvAsString(kvs []*commonpb.KeyValue, key string) string {
	for _, kv := range kvs {
		if kv.Key == key {
			return kv.Value.GetStringValue()
		}
	}
	return ""
}

func kvAsInt(kvs []*commonpb.KeyValue, key string) int64 {
	for _, kv := range kvs {
		if kv.Key == key {
			return kv.Value.GetIntValue()
		}
	}
	return 0
}

func kvAsStringArray(kvs []*commonpb.KeyValue, key string) []string {
	for _, kv := range kvs {
		if kv.Key != key {
			continue
		}
		arr := kv.Value.GetArrayValue()
		if arr == nil {
			return nil
		}
		out := make([]string, 0, len(arr.Values))
		for _, v := range arr.Values {
			out = append(out, v.GetStringValue())
		}
		return out
	}
	return nil
}

type fakeProvider struct {
	data map[string]*ControllerClusters
}

func (f *fakeProvider) FetchAllClusters() map[string]*ControllerClusters { return f.data }

func TestEmitter_EmitsOneLogRecordPerEligibleNode(t *testing.T) {
	srv := &capturingLogsServer{}
	lis, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)
	grpcSrv := grpc.NewServer()
	collogspb.RegisterLogsServiceServer(grpcSrv, srv)
	go grpcSrv.Serve(lis)
	defer grpcSrv.Stop()

	cluster := &api.Cluster{
		ClusterID:   42,
		ClusterName: "prod-galera",
		ClusterType: "GALERA",
		Vendor:      "percona",
		Tags:        []string{"customer-acme", "env-prod"},
		Hosts: []*api.Host{
			{
				WithClassName: &api.WithClassName{ClassName: "CmonGaleraHost"},
				HostID:        1001,
				Hostname:      "db-1",
				IP:            "10.0.1.1",
				Port:          3306,
				HostStatus:    "CmonHostOnline",
				Nodetype:      "galera",
			},
			{
				WithClassName: &api.WithClassName{ClassName: "CmonProxySqlHost"},
				HostID:        1002,
				Hostname:      "proxy-1",
				IP:            "10.0.1.2",
				Port:          6033,
				HostStatus:    "CmonHostOnline",
				Nodetype:      "proxysql",
			},
			{
				// Controllers are skipped.
				WithClassName: &api.WithClassName{ClassName: "CmonMySqlHost"},
				Hostname:      "ctrl",
				IP:            "10.0.1.254",
				Nodetype:      "controller",
			},
		},
	}

	prov := &fakeProvider{data: map[string]*ControllerClusters{
		"ctrl-1.example:9500": {
			ControllerID: "ctrl-xid-1",
			Clusters:     []*api.Cluster{cluster},
			HostStats: map[uint64]*HostHardwareStats{
				1001: {VCPU: intPtr(8), RAMMB: intPtr(16384), VolumeGB: intPtr(200)},
				// 1002 intentionally omitted to exercise the nil-hw path.
			},
		},
	}}

	em := NewEmitter(prov, lis.Addr().String(), time.Hour, "emit-1")
	em.logger = zap.NewNop().Sugar()
	em.emitFromData(prov.FetchAllClusters())

	require.Eventually(t, func() bool { return len(srv.requests) == 1 }, time.Second, 10*time.Millisecond)

	req := srv.requests[0]
	require.Len(t, req.ResourceLogs, 1)
	rl := req.ResourceLogs[0]

	// Resource carries service identity.
	assert.Equal(t, "cmon-proxy", kvAsString(rl.Resource.Attributes, "service.name"))
	assert.Equal(t, "emit-1", kvAsString(rl.Resource.Attributes, "service.instance.id"))

	require.Len(t, rl.ScopeLogs, 1)
	records := rl.ScopeLogs[0].LogRecords
	require.Len(t, records, 2, "controller host must be skipped; 2 eligible nodes remain")

	// Index records by node_id for deterministic assertions.
	byID := map[string]int{}
	for i, r := range records {
		byID[kvAsString(r.Body.GetKvlistValue().Values, "node_id")] = i
	}

	// Galera DB host — has hardware stats.
	db := records[byID["ctrl-xid-1:10.0.1.1"]]
	assert.NotZero(t, db.TimeUnixNano)
	assert.Equal(t, "INFO", db.SeverityText)
	assert.Equal(t, "ctrl-xid-1", kvAsString(db.Attributes, "cc.controller.id"))
	assert.Equal(t, int64(42), kvAsInt(db.Attributes, "cc.cluster.id"))
	assert.Equal(t, "prod-galera", kvAsString(db.Attributes, "cc.cluster.name"))
	assert.Equal(t, "GALERA", kvAsString(db.Attributes, "cc.cluster.type"))
	assert.Equal(t, "percona", kvAsString(db.Attributes, "cc.db.vendor"))

	dbBody := db.Body.GetKvlistValue().Values
	assert.Equal(t, "db-1", kvAsString(dbBody, "hostname"))
	assert.Equal(t, int64(3306), kvAsInt(dbBody, "port"))
	assert.Equal(t, "database", kvAsString(dbBody, "node_role"))
	assert.Equal(t, "CmonGaleraHost", kvAsString(dbBody, "node_class"))
	assert.Equal(t, "CmonHostOnline", kvAsString(dbBody, "node_status"))
	assert.Equal(t, int64(8), kvAsInt(dbBody, "vcpu"))
	assert.Equal(t, int64(16384), kvAsInt(dbBody, "ram_mb"))
	assert.Equal(t, int64(200), kvAsInt(dbBody, "volume_gb"))
	assert.Equal(t, []string{"customer-acme", "env-prod"}, kvAsStringArray(dbBody, "tags"))

	// ProxySQL host — no hardware stats configured; ram_mb / volume_gb absent.
	proxy := records[byID["ctrl-xid-1:10.0.1.2"]]
	proxyBody := proxy.Body.GetKvlistValue().Values
	assert.Equal(t, "proxysql", kvAsString(proxyBody, "node_role"))
	assert.Equal(t, int64(0), kvAsInt(proxyBody, "ram_mb"), "missing ram_mb returns zero-int on lookup")
	// Absence check — ensure we didn't emit a ram_mb KV at all when hw was nil.
	for _, kv := range proxyBody {
		assert.NotEqual(t, "vcpu", kv.Key, "vcpu must be absent when HostStats is missing")
		assert.NotEqual(t, "ram_mb", kv.Key, "ram_mb must be absent when HostStats is missing")
		assert.NotEqual(t, "volume_gb", kv.Key, "volume_gb must be absent when HostStats is missing")
	}
}
