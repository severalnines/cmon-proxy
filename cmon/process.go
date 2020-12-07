package cmon

import (
	"fmt"

	"github.com/severalnines/cmon-proxy/cmon/api"
)

func (client *Client) GetSqlProcesses(req *api.GetSqlProcessesRequest) (*api.GetSqlProcessesResponse, error) {
	req.Operation = "getSqlProcesses"
	if req.WithClusterID == nil || req.WithClusterID.ClusterID < 1 {
		return nil, fmt.Errorf("invalid cluster id")
	}
	res := &api.GetSqlProcessesResponse{}
	if err := client.Request(api.ModuleClusters, req, res, false); err != nil {
		return nil, err
	}
	if res.RequestStatus != api.RequestStatusOk {
		return nil, api.NewErrorFromResponseData(res.WithResponseData)
	}
	return res, nil
}

func (client *Client) GetTopQueries(req *api.GetTopQueriesRequest) (*api.GetTopQueriesResponse, error) {
	req.Operation = "getTopQueries"
	if req.WithClusterID == nil || req.WithClusterID.ClusterID < 1 {
		return nil, fmt.Errorf("invalid cluster id")
	}
	res := &api.GetTopQueriesResponse{}
	if err := client.Request(api.ModuleClusters, req, res, false); err != nil {
		return nil, err
	}
	if res.RequestStatus != api.RequestStatusOk {
		return nil, api.NewErrorFromResponseData(res.WithResponseData)
	}
	return res, nil
}
