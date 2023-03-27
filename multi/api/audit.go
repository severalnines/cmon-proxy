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

// AuditEntryExt is a cmon audit entry extended by controller ID / URL fields
type AuditEntryExt struct {
	*WithControllerID
	*cmonapi.AuditEntry
}

type AuditEntryListRequest struct {
	ListRequest `json:",inline"`
}

type AuditEntryListReply struct {
	ListResponse `json:",inline"`
	Entries      []*AuditEntryExt             `json:"entries"`
	LastUpdated  map[string]*cmonapi.NullTime `json:"last_updated"`
}

func (ae *AuditEntryListReply) Add(entry *cmonapi.AuditEntry, controllerUrl, controllerId string) {
	if len(ae.Entries) < 1 {
		ae.Entries = make([]*AuditEntryExt, 0, 16)
	}
	ae.Entries = append(ae.Entries, &AuditEntryExt{
		WithControllerID: &WithControllerID{
			ControllerURL: controllerUrl,
			ControllerID:  controllerId,
		},
		AuditEntry: entry.Copy(),
	})
}
