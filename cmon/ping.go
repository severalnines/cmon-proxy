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
	"github.com/severalnines/cmon-proxy/cmon/api"
)

func (client *Client) Ping() (*api.PingResponse, error) {
	req := api.PingRequest{
		WithOperation:       &api.WithOperation{Operation: "ping"},
		WithClusterIDForced: &api.WithClusterIDForced{}}
	res := &api.PingResponse{}
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

// PingWithControllers combines ping and getControllers operations for a complete status
func (client *Client) PingWithControllers() (*api.PingResponse, []*api.PoolController, error) {
	// Get ping response
	pingRes, err := client.Ping()
	if err != nil {
		return nil, nil, err
	}

	// Then get controllers information
	controllersReq := &api.GetControllersRequest{
		WithOperation: &api.WithOperation{},
		ControllerID:  0, // Get all controllers
	}
	
	controllersRes, err := client.GetControllers(controllersReq)
	if err != nil {
		// If controllers request fails, still return ping data but with empty controllers
		return pingRes, []*api.PoolController{}, nil
	}

	return pingRes, controllersRes.Controllers, nil
}

