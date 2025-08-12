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

import cmonapi "github.com/severalnines/cmon-proxy/cmon/api"

type CmonStatus string

var (
	CmonStatuses = []CmonStatus{
		Ok,
		Failed,
		AuthenticationError,
	}
)

// String implements Stringer interface
func (st CmonStatus) String() string {
	return string(st)
}

const (
	Ok                  CmonStatus = "ok"
	Failed              CmonStatus = "failed"
	AuthenticationError CmonStatus = "authentication-error"
)

type ControllerStatusRequest struct {
	ForceUpdateRequest `json:",inline"`
	ForceLicenseCheck  bool `json:"force_license_check"`
}

type ControllerStatus struct {
	Xid           string                    `json:"xid"`
    PoolId        string                    `json:"pool_id,omitempty"`
	ControllerID  string                    `json:"controller_id"`
	Name          string                    `json:"controller_name"`
	Url           string                    `json:"url"`
	FrontendUrl   string                    `json:"frontend_url,omitempty"`
	Version       string                    `json:"version"`
	StatusMessage string                    `json:"status_message"`
	Status        CmonStatus                `json:"status"`
	LastUpdated   cmonapi.NullTime          `json:"last_updated"`
	LastSeen      cmonapi.NullTime          `json:"last_seen"`
	License       *cmonapi.CmonLicense      `json:"license"`
	LicenseCheck  *cmonapi.CmonLicenseCheck `json:"license_check"`
}

type ControllerStatusList struct {
	Controllers []*ControllerStatus `json:"controllers"`
}
