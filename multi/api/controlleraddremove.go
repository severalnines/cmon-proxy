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
}

// RemoveControllerRequest can be sent to remove a controller by URL
type RemoveControllerRequest struct {
	Url string `json:"url"`
	Xid string `json:"xid"`
}
