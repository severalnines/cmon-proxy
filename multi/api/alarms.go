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

type AlarmsOverview struct {
	// Alarm counts by severity
	AlarmCounts map[string]int `json:"alarms_count"`
	// Alarm counts by type
	AlarmTypes map[string]int `json:"alarm_types"`

	// Alarm counts by controller
	AlarmCountsByController map[string]*AlarmsOverview `json:"by_controller,omitempty"`

	// for the "technology" filters
	ByClusterType map[string]*AlarmsOverview `json:"by_cluster_type,omitempty"`
}

// AlarmExt is a cmon alarm extended by controller ID / URL fields
type AlarmExt struct {
	*WithControllerID
	*cmonapi.Alarm
}

type AlarmListRequest struct {
	ListRequest `json:",inline"`
}

type AlarmListReply struct {
	ListResponse `json:",inline"`
	Alarms       []*AlarmExt                  `json:"alarms"`
	LastUpdated  map[string]*cmonapi.NullTime `json:"last_updated"`
}

func (al *AlarmListReply) Add(alarm *cmonapi.Alarm, controllerUrl, controllerId string) {
	if len(al.Alarms) < 1 {
		al.Alarms = make([]*AlarmExt, 0, 16)
	}
	al.Alarms = append(al.Alarms, &AlarmExt{
		WithControllerID: &WithControllerID{
			ControllerURL: controllerUrl,
			ControllerID:  controllerId,
		},
		Alarm: alarm.Copy(),
	})
}
