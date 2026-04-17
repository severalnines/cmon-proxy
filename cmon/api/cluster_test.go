package api

import (
	"encoding/json"
	"testing"
)

func TestGetMeteringDataResponse_UnmarshalClusterTypeFromNumber(t *testing.T) {
	payload := []byte(`{
		"request_status":"Ok",
		"clusters":[
			{
				"cluster_id":1,
				"cluster_name":"prod",
				"cluster_type":1,
				"vendor":"mariadb",
				"hosts":[]
			}
		]
	}`)

	var response GetMeteringDataResponse
	if err := json.Unmarshal(payload, &response); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if len(response.Clusters) != 1 {
		t.Fatalf("expected 1 cluster, got %d", len(response.Clusters))
	}

	if response.Clusters[0].ClusterType == "" {
		t.Fatal("expected numeric cluster_type to be preserved as a non-empty string")
	}
}
