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

// AuthenticateRequest the one to star authentication (key or password based)
type AuthenticateRequest struct {
	*WithOperation `json:",inline"`

	UserName string `json:"user_name"`
	Password string `json:"password"`
	LdapOnly bool   `json:"ldap_only,omitempty"`
}

// Authenticate2Request is requested for key based authentication
type Authenticate2Request struct {
	*WithOperation `json:",inline"`

	Signature string `json:"signature"`
}

type WhoAmIRequest struct {
	*WithOperation `json:",inline"`
}

// AuthenticateResponse the data we get from server for auth reqs
type AuthenticateResponse struct {
	*WithControllerID `json:",inline"`
	*WithResponseData `json:",inline"`

	Challenge string `json:"challenge"`
	User      *User  `json:"user"`
}
