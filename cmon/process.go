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

func (client *Client) GetSqlProcesses(req *api.GetSqlProcessesRequest) (*api.GetSqlProcessesResponse, error) {
	req.Operation = "getSqlProcesses"
	if req.WithClusterID == nil || req.WithClusterID.ClusterID < 1 {
		return nil, fmt.Errorf("invalid cluster id")
	}
	res := &api.GetSqlProcessesResponse{}
	if err := client.Request(api.ModuleClusters, req, res); err != nil {
		return nil, err
	}
	if res.WithResponseData == nil {
		return nil, api.NewError(api.RequestStatusUnknownError, "empty response data")
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
	if err := client.Request(api.ModuleClusters, req, res); err != nil {
		return nil, err
	}
	if res.WithResponseData == nil {
		return nil, api.NewError(api.RequestStatusUnknownError, "empty response data")
	}
	if res.RequestStatus != api.RequestStatusOk {
		return nil, api.NewErrorFromResponseData(res.WithResponseData)
	}
	return res, nil
}
