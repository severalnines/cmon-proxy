package api

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
	cmonapi "github.com/severalnines/cmon-proxy/cmon/api"
)

// LogExt is a cmon log extended by controller ID / URL fields
type LogExt struct {
	*WithControllerID
	*cmonapi.Log
}

type LogListRequest struct {
	ListRequest `json:",inline"`
}

type LogListReply struct {
	ListResponse `json:",inline"`
	Logs         []*LogExt                    `json:"logs"`
	LastUpdated  map[string]*cmonapi.NullTime `json:"last_updated"`
}

func (lo *LogListReply) Add(log *cmonapi.Log, controllerUrl, controllerId string) {
	if len(lo.Logs) < 1 {
		lo.Logs = make([]*LogExt, 0, 16)
	}
	lo.Logs = append(lo.Logs, &LogExt{
		WithControllerID: &WithControllerID{
			ControllerURL: controllerUrl,
			ControllerID:  controllerId,
		},
		Log: log.Copy(),
	})
}
