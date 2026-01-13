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

// UpdateInstancePreferencesRequest is used to update preferences for an instance
type UpdateInstancePreferencesRequest struct {
	ControllerXid string                 `json:"controllerXid"`
	Preferences   map[string]interface{} `json:"preferences"`
}

// GetInstancePreferencesResponse returns preferences for an instance
type GetInstancePreferencesResponse struct {
	*cmonapi.WithResponseData `json:",inline"`
	Preferences                map[string]interface{} `json:"preferences"`
}

// UpdateInstancePreferencesResponse confirms preference update
type UpdateInstancePreferencesResponse struct {
	*cmonapi.WithResponseData `json:",inline"`
	Preferences                map[string]interface{} `json:"preferences"`
}

