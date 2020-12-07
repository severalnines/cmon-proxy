package cmon

import (
	"fmt"

	"github.com/severalnines/cmon-proxy/cmon/api"
)

func (client *Client) GetStatByName(req *api.GetStatByNameRequest) (*api.GetStatByNameResponse, error) {
	req.Operation = "statByName"
	if req.WithClusterID == nil || req.WithClusterID.ClusterID < 1 {
		return nil, fmt.Errorf("invalid cluster id")
	}
	res := &api.GetStatByNameResponse{}
	if err := client.Request(api.ModuleStat, req, res, false); err != nil {
		return nil, err
	}
	if res.RequestStatus != api.RequestStatusOk {
		return nil, api.NewErrorFromResponseData(res.WithResponseData)
	}
	return res, nil
}
