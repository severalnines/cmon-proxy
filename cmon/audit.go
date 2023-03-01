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

func (client *Client) GetAuditEntries(clusterId uint64) (*api.GetAuditEntriesReply, error) {
	req := &api.GetAuditEntriesRequest{
		WithOperation: &api.WithOperation{
			Operation: "getEntries",
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
	res := &api.GetAuditEntriesReply{}
	if err := client.Request(api.ModuleAudit, req, res); err != nil {
		return nil, err
	}
	if res.RequestStatus != api.RequestStatusOk {
		return nil, api.NewErrorFromResponseData(res.WithResponseData)
	}
	return res, nil
}
