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

type LoginRequest struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	LdapOnly bool   `json:"ldap_only,omitempty"`
	Xid      string `json:"xid,omitempty"`
}

type LoginResponse struct {
	*cmonapi.WithResponseData `json:",inline"`

	User       *config.ProxyUser `json:"user,omitempty"`
	Elevated   bool              `json:"elevated,omitempty"`
	AuthErrors []string          `json:"auth_errors,omitempty"`
}

type UpdateUserRequest struct {
	User *config.ProxyUser `json:"user,omitempty"`
}
type UserWithPassword struct {
	*config.ProxyUser `json:",inline"`
	Password          string `json:"password,omitempty"`
}
type RegisterUserRequest struct {
	User *UserWithPassword `json:"user,omitempty"`
}

type SetPasswordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

type ElevateSessionResponse struct {
	*cmonapi.WithResponseData `json:",inline"`
	Elevated                  bool `json:"elevated,omitempty"`
}
