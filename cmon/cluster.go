package cmon
// Copyright 2022 Severalnines AB
//
// This file is part of cmon-proxy.
//
// cmon-proxy is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 2 of the License.
//
// cmon-proxy is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with cmon-proxy. If not, see <https://www.gnu.org/licenses/>.


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
