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

func (client *Client) GetControllers(req *api.GetControllersRequest) (*api.GetControllersResponse, error) {
	if req.WithOperation == nil {
		req.WithOperation = &api.WithOperation{}
	}
	req.Operation = "listcontrollers"

	// Set controller_id to 0 if not provided (optional parameter)
	if req.ControllerID == 0 {
		req.ControllerID = 0 // 0 means get all controllers
	}

	res := &api.GetControllersResponse{}
	if err := client.Request(api.ModulePoolControllers, req, res); err != nil {
		return nil, err
	}

	return res, nil
}