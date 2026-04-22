package otel

import (
	"testing"

	"github.com/severalnines/cmon-proxy/cmon/api"
)

// helper to build a Host with a given class_name for eligibility tests
func testHost(className, nodetype, role, elasticRoles string) *api.Host {
	return &api.Host{
		WithClassName: &api.WithClassName{ClassName: className},
		Nodetype:      nodetype,
		Role:          role,
		ElasticRoles:  elasticRoles,
	}
}

func TestIsEligibleHost_ClassNameGate(t *testing.T) {
	cases := []struct {
		name      string
		className string
		want      bool
	}{
		// DB classes — eligible
		{"mysql", "CmonMySqlHost", true},
		{"galera", "CmonGaleraHost", true},
		{"postgres (covers Timescale too)", "CmonPostgreSqlHost", true},
		{"redis data (covers Valkey data)", "CmonRedisHost", true},
		{"redis sharded (wire: no Cmon prefix)", "RedisShardedHost", true},
		{"redis sharded (wire: Cmon prefix future-proof)", "CmonRedisShardedHost", true},
		// Proxy class — eligible
		{"proxysql", "CmonProxySqlHost", true},
		// Intentionally excluded classes
		{"redis sentinel (covers Valkey sentinel)", "CmonRedisSentinelHost", false},
		{"prometheus sidecar", "CmonPrometheusHost", false},
		{"empty class", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := IsEligibleHost(testHost(tc.className, "", "", ""))
			if got != tc.want {
				t.Fatalf("IsEligibleHost(%q) = %v, want %v", tc.className, got, tc.want)
			}
		})
	}
}

func TestIsEligibleHost_SkipsController(t *testing.T) {
	// A host with nodetype=="controller" is the CMON controller itself,
	// never a billable node regardless of class.
	h := testHost("CmonMySqlHost", "controller", "", "")
	if IsEligibleHost(h) {
		t.Fatalf("controller host must not be eligible")
	}
}

func TestIsEligibleHost_MongoShardsRoleGate(t *testing.T) {
	cases := []struct {
		name string
		role string
		want bool
	}{
		{"shard data (shardsvr)", "shardsvr", true},
		{"config server (configsvr) — excluded", "configsvr", false},
		{"mongos router — excluded", "mongos", false},
		{"arbiter — excluded (no data)", "arbiter", false},
		{"plain replicaset (role empty)", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := IsEligibleHost(testHost("CmonMongoHost", "", tc.role, ""))
			if got != tc.want {
				t.Fatalf("Mongo role=%q IsEligibleHost = %v, want %v", tc.role, got, tc.want)
			}
		})
	}
}

func TestIsEligibleHost_ElasticDataRoleGate(t *testing.T) {
	cases := []struct {
		name  string
		roles string
		want  bool
	}{
		{"plain data", "data", true},
		{"data_hot", "data_hot", true},
		{"data_content alone", "data_content", true},
		{"data combined with other roles", "master-data-ingest", true},
		{"data_frozen combined", "master-data_frozen", true},
		{"master only", "master", false},
		{"ingest only", "ingest", false},
		{"coordinator_only", "coordinator_only", false},
		{"master+ingest (no data)", "master-ingest", false},
		{"ml+transform", "ml-transform", false},
		{"empty roles — default to eligible (field missing upstream)", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := IsEligibleHost(testHost("CmonElasticHost", "", "", tc.roles))
			if got != tc.want {
				t.Fatalf("Elastic roles=%q IsEligibleHost = %v, want %v", tc.roles, got, tc.want)
			}
		})
	}
}

func TestElasticHasDataRole_SubstringGuard(t *testing.T) {
	// "data_content" must match as a full segment, not as a substring of
	// "data_contents" or similar. Quick guard against naive Contains() drift.
	if !elasticHasDataRole("data_content") {
		t.Fatal("data_content must be a data role")
	}
	if elasticHasDataRole("daddata") {
		t.Fatal("arbitrary substring must not count as a data role")
	}
}

type fakeMeteringClient struct {
	meteringResp *api.GetMeteringDataResponse
	cpuInfoResp  *api.GetCpuPhysicalInfoResponse
}

func (f *fakeMeteringClient) GetMeteringData(*api.GetMeteringDataRequest) (*api.GetMeteringDataResponse, error) {
	return f.meteringResp, nil
}

func (f *fakeMeteringClient) GetCpuPhysicalInfo(*api.GetCpuPhysicalInfoRequest) (*api.GetCpuPhysicalInfoResponse, error) {
	return f.cpuInfoResp, nil
}

func TestFetchMeteringData_UsesCpuInfoWhenMeteringDataLacksNCPUs(t *testing.T) {
	client := &fakeMeteringClient{
		meteringResp: &api.GetMeteringDataResponse{
			WithResponseData: &api.WithResponseData{RequestStatus: api.RequestStatusOk},
			Clusters: []*api.MeteringCluster{
				{
					ClusterID:   7,
					ClusterName: "prod",
					ClusterType: "GALERA",
					Vendor:      "mariadb",
					Hosts: []*api.MeteringHost{
						{
							ClassName:  "CmonGaleraHost",
							HostID:     42,
							Hostname:   "db-1",
							IP:         "10.0.0.10",
							Port:       3306,
							HostStatus: "CmonHostOnline",
							NodeType:   "galera",
						},
					},
				},
			},
		},
		cpuInfoResp: &api.GetCpuPhysicalInfoResponse{
			WithResponseData: &api.WithResponseData{RequestStatus: api.RequestStatusOk},
			Data: []*api.CpuPhysicalInfo{
				{HostID: 42, PhysicalCPUID: 0, CpuCores: 4, Siblings: 8},
				{HostID: 42, PhysicalCPUID: 1, CpuCores: 4, Siblings: 8},
			},
		},
	}

	_, hostStats, err := fetchMeteringData(client)
	if err != nil {
		t.Fatalf("fetchMeteringData returned error: %v", err)
	}

	stats, ok := hostStats[42]
	if !ok {
		t.Fatal("expected host stats for host 42")
	}

	if stats.VCPU == nil || *stats.VCPU != 16 {
		t.Fatalf("expected vcpu fallback of 16, got %#v", stats.VCPU)
	}
}
