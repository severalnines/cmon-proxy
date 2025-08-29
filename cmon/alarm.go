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
	"errors"

	"github.com/severalnines/cmon-proxy/cmon/api"
)

func (client *Client) GetAlarms(clusterId uint64) (*api.GetAlarmsReply, error) {
    if client == nil || client.Instance == nil {
        return nil, api.NewError(api.RequestStatusUnknownError, "client is nil")
    }
	req := &api.GetAlarmsRequest{
		WithOperation: &api.WithOperation{
			Operation: "getAlarms",
		},
		WithClusterID: &api.WithClusterID{
			ClusterID: clusterId,
		},
	}
	if clusterId > 0 {
		if err := api.CheckClusterID(req); err != nil {
			return nil, err
		}
	}
	res := &api.GetAlarmsReply{}
	if err := client.Request(api.ModuleAlarm, req, res); err != nil {
		return nil, err
	}

	if res == nil {
		return nil, errors.New("got nil GetAlarmsReply")
	}

	if res.WithResponseData == nil {
		return nil, api.NewError(api.RequestStatusUnknownError, "empty response data")
	}
	if res.RequestStatus != api.RequestStatusOk {
		return nil, api.NewErrorFromResponseData(res.WithResponseData)
	}
	return res, nil
}
