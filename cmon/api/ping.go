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


type PingRequest struct {
	*WithOperation       `json:",inline"`
	*WithClusterIDForced `json:",inline"`
}

type PingResponse struct {
	*WithControllerID `json:",inline"`
	*WithResponseData `json:",inline"`

	Name    string `json:"package_name"`
	Version string `json:"package_version"`
}

type InfoPingRequest struct {
	*WithOperation       `json:",inline"`
}

type InfoPingResponse struct {
	*WithControllerID `json:",inline"`
	*WithResponseData `json:",inline"`

	Name    string `json:"package_name"`
	Version string `json:"package_version"`
    // ControllersPool is returned by /info operation: ping and represents
    // the other controllers in the pool seen by this controller
    ControllersPool []ControllerPoolEntry `json:"controllers_pool,omitempty"`
    // Top-level attributes about the current controller instance
    Hostname   string `json:"hostname,omitempty"`
    Port       int    `json:"port,omitempty"`
    RpcV2Port  int    `json:"rpcv2_port,omitempty"`
}

// ControllerPoolEntry describes one controller entry inside controllers_pool
type ControllerPoolEntry struct {
    ControllerID uint64 `json:"controller_id"`
    Hostname     string `json:"hostname"`
    Port         int    `json:"port"`
    RpcV2Port    int    `json:"rpcv2_port,omitempty"`
    Properties   string `json:"properties"`
    ReportTs     string `json:"report_ts"`
    Status       string `json:"status"`
}
