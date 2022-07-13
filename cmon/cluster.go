package cmon

import (
	"fmt"

	"github.com/severalnines/cmon-proxy/cmon/api"
)

func (client *Client) GetClusterInfo(req *api.GetClusterInfoRequest) (*api.GetClusterInfoResponse, error) {
	if req.WithOperation == nil {
		req.WithOperation = &api.WithOperation{}
	}
	req.Operation = "getClusterInfo"
	if req.WithClusterID == nil || req.WithClusterID.ClusterID < 1 {
		return nil, fmt.Errorf("invalid cluster id")
	}
	res := &api.GetClusterInfoResponse{}
	if err := client.Request(api.ModuleClusters, req, res); err != nil {
		return nil, err
	}
	if res.RequestStatus != api.RequestStatusOk {
		return nil, api.NewErrorFromResponseData(res.WithResponseData)
	}
	return res, nil
}

func (client *Client) GetAllClusterInfo(req *api.GetAllClusterInfoRequest) (*api.GetAllClusterInfoResponse, error) {
	if req == nil {
		req = &api.GetAllClusterInfoRequest{}
	}
	if req.WithOperation == nil {
		req.WithOperation = &api.WithOperation{}
	}
	req.Operation = "getAllClusterInfo"
	res := &api.GetAllClusterInfoResponse{}
	if err := client.Request(api.ModuleClusters, req, res); err != nil {
		return nil, err
	}
	if res.RequestStatus != api.RequestStatusOk {
		return nil, api.NewErrorFromResponseData(res.WithResponseData)
	}
	return res, nil
}

func (client *Client) CreateDatabase(req *api.CreateDatabaseRequest) (*api.CreateDatabaseResponse, error) {
	if req.WithOperation == nil {
		req.WithOperation = &api.WithOperation{}
	}
	req.Operation = "createDatabase"
	if req.WithClusterID == nil || req.WithClusterID.ClusterID < 1 {
		return nil, fmt.Errorf("invalid cluster id")
	}
	res := &api.CreateDatabaseResponse{}
	if err := client.Request(api.ModuleClusters, req, res); err != nil {
		return nil, err
	}
	if res.RequestStatus != api.RequestStatusOk {
		return nil, api.NewErrorFromResponseData(res.WithResponseData)
	}
	return res, nil
}

func (client *Client) ListDatabases(req *api.ListDatabasesRequest) (*api.ListDatabasesResponse, error) {
	if req.WithClusterID == nil || req.WithClusterID.ClusterID < 1 {
		return nil, fmt.Errorf("invalid cluster id")
	}
	c, err := client.GetClusterInfo(&api.GetClusterInfoRequest{
		WithClusterID: req.WithClusterID,
		WithDatabases: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch databases list from cmon: %s", err.Error())
	}
	if c.Cluster.Databases == nil {
		return nil, fmt.Errorf("cmon returned null instead of databases list")
	}
	return &api.ListDatabasesResponse{
		WithResponseData: c.WithResponseData,
		Databases:        c.Cluster.Databases,
	}, nil
}
