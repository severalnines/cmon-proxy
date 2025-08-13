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
	"github.com/severalnines/cmon-proxy/config"
)

// AddControllerRequest can be used to add or test a cmon instance to the system
type AddControllerRequest struct {
	Controller *config.CmonInstance `json:"controller"`
}

// AddControllerResponse contains the controller status message
type AddControllerResponse struct {
	*cmonapi.Error

	Controller *ControllerStatus `json:"controller"`
    Pool       *PoolInfo         `json:"pool,omitempty"`
}

// AddControllersFromPoolRequest instructs the server to discover the pool via /info ping
// and add all controllers from that pool using the provided controller credentials.
// The base name is taken from Controller.Name; when present the added controllers will be named
// baseName_1, baseName_2, ... according to their index in the discovered list.
type AddControllersFromPoolRequest struct {
    Controller *config.CmonInstance `json:"controller"`
}

// AddControllersFromPoolResponse reports added controllers and failures
type AddControllersFromPoolResponse struct {
    *cmonapi.Error

    Added   []*ControllerStatus `json:"added"`
    Failed  []string            `json:"failed"`
}

// PoolInfo carries information about the controller pool discovered via /info ping
type PoolInfo struct {
    Cmons []PoolCmon `json:"cmons"`
}

// PoolCmon represents a single controller in the pool response
type PoolCmon struct {
    ControllerID uint64 `json:"controller_id"`
    Hostname     string `json:"hostname"`
    Port         int    `json:"port"`
    RpcV2Port    int    `json:"rpcv2_port,omitempty"`
    Properties   string `json:"properties"`
    ReportTs     string `json:"report_ts"`
    Status       string `json:"status"`
}

// RemoveControllerRequest can be sent to remove a controller by URL
type RemoveControllerRequest struct {
	ControllerXid string `json:"controllerXid"`
}
