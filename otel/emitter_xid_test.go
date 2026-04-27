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
	"net"
	"testing"
	"time"

	"github.com/severalnines/cmon-proxy/cmon/api"
	"github.com/stretchr/testify/require"
	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

// TestEmitter_SkipsControllersWithEmptyID is the regression lock for the
// xid-fallback bug: if a controller reaches the emitter with ControllerID=""
// (e.g. a future ClusterDataProvider that forgets to populate it, or a
// RouterAdapter regression), we MUST refuse to emit rather than leak a blank
// or fall back to a router URL. Emitting an empty or URL-shaped
// cc.controller.id would poison cc-telemetry's node_snapshots keying and
// create a ghost-controller's worth of rows the instant xid settles.
func TestEmitter_SkipsControllersWithEmptyID(t *testing.T) {
	srv := &capturingLogsServer{}
	lis, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)
	grpcSrv := grpc.NewServer()
	collogspb.RegisterLogsServiceServer(grpcSrv, srv)
	go grpcSrv.Serve(lis)
	defer grpcSrv.Stop()

	cluster := &api.Cluster{
		ClusterID:   7,
		ClusterName: "prod",
		ClusterType: "GALERA",
		Vendor:      "mariadb",
		Hosts: []*api.Host{
			{
				WithClassName: &api.WithClassName{ClassName: "CmonGaleraHost"},
				HostID:        1,
				Hostname:      "db-1",
				IP:            "10.0.0.1",
				Port:          3306,
				HostStatus:    "CmonHostOnline",
				Nodetype:      "galera",
			},
		},
	}

	prov := &fakeProvider{data: map[string]*ControllerClusters{
		// Empty ControllerID — must be skipped entirely.
		"ctrl-unsettled.example:9500": {
			ControllerID: "",
			Clusters:     []*api.Cluster{cluster},
		},
		// Well-formed peer — proves we only skipped the offending entry.
		"ctrl-good.example:9500": {
			ControllerID: "ctrl-xid-good",
			Clusters:     []*api.Cluster{cluster},
		},
	}}

	em := NewEmitter(prov, lis.Addr().String(), time.Hour, "test")
	em.logger = zap.NewNop().Sugar()
	em.emitFromData(prov.FetchAllClusters())

	require.Eventually(t, func() bool { return len(srv.requests) == 1 }, time.Second, 10*time.Millisecond)

	req := srv.requests[0]
	require.Len(t, req.ResourceLogs, 1)
	records := req.ResourceLogs[0].ScopeLogs[0].LogRecords
	require.Len(t, records, 1, "only the well-formed controller's node should be emitted")

	attrs := records[0].Attributes
	require.Equal(t, "ctrl-xid-good", kvAsString(attrs, "cc.controller.id"))
	// The bug we guard against: a URL-shaped value for cc.controller.id.
	require.NotContains(t, kvAsString(attrs, "cc.controller.id"), "://")
	require.NotEmpty(t, kvAsString(attrs, "cc.controller.id"))
}
