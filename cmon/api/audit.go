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

type GetAuditEntriesRequest struct {
	*WithOperation `json:",inline"`
	*WithClusterID `json:",inline"`
}

type GetAuditEntriesReply struct {
	*WithControllerID `json:",inline"`
	*WithResponseData `json:",inline"`

	AuditEntries []*AuditEntry `json:"audit_entries"`
}

// AuditEntry struct.
type AuditEntry struct {
	ClusterID      int64    `json:"cluster_id"`
	ClientHostname string   `json:"client_hostname"`
	ReportTs       NullTime `json:"report_ts"`
	EntryType      string   `json:"entry_type"`
	MessageText    string   `json:"message_text"`
	Username       string   `json:"username"`
}

func (a *AuditEntry) Copy() *AuditEntry {
	return &AuditEntry{
		ClusterID:      a.ClusterID,
		ClientHostname: a.ClientHostname,
		ReportTs:       a.ReportTs,
		EntryType:      a.EntryType,
		MessageText:    a.MessageText,
		Username:       a.Username,
	}
}
