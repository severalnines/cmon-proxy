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


type CreateAccountRequest struct {
	*WithOperation `json:",inline"`
	*WithClusterID `json:",inline"`

	Account *Account `json:"account"`
}

type CreateAccountResponse struct {
	*WithControllerID `json:",inline"`
	*WithResponseData `json:",inline"`

	Account *Account `json:"account"`
}

type Account struct {
	*WithClassName `json:",inline"`

	Grants             string `json:"grants,omitempty"`
	HostAllow          string `json:"host_allow,omitempty"`
	OwnDatabase        string `json:"own_database,omitempty"`
	Password           string `json:"password,omitempty"`
	PasswordExpired    bool   `json:"password_expired,omitempty"`
	UserName           string `json:"user_name,omitempty"`
	SystemUser         bool   `json:"system_user,omitempty"`
	MaxConnections     int64  `json:"max_connections,omitempty"`
	MaxQuestions       int64  `json:"max_questions,omitempty"`
	MaxUpdates         int64  `json:"max_updates,omitempty"`
	MaxUserConnections int64  `json:"max_user_connections,omitempty"`
}

type ListAccountsRequest struct {
	*WithOperation `json:",inline"`
	*WithClusterID `json:",inline"`
	*WithLimit     `json:",inline"`
}

type ListAccountsResponse struct {
	*WithControllerID `json:",inline"`
	*WithResponseData `json:",inline"`
	*WithTotal        `json:",inline"`

	Accounts []*Account `json:"accounts"`
}

type DeleteAccountRequest struct {
	*WithOperation `json:",inline"`
	*WithClusterID `json:",inline"`

	Account *Account `json:"account"`
}

type DeleteAccountResponse struct {
	*WithControllerID `json:",inline"`
	*WithResponseData `json:",inline"`
}
