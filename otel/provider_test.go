package otel

import (
	"testing"

	"github.com/severalnines/cmon-proxy/cmon/api"
)

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
