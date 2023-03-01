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

type GetLogsRequest struct {
	*WithOperation `json:",inline"`
	*WithClusterID `json:",inline"`
}

type GetLogsReply struct {
	*WithControllerID `json:",inline"`
	*WithResponseData `json:",inline"`

	Logs []*Log `json:"log_entries"`
}

// Log struct.
type Log struct {
	LogId        int64        `json:"log_id"`
	LogClass     string       `json:"log_class"`
	Created      NullTime     `json:"created"`
	Severity     string       `json:"severity"`
	LogSpecifics LogSpecifics `json:"log_specifics"`
	LogOrigins   LogOrigins   `json:"log_origins"`
}

// LogSpecifics struct.
type LogSpecifics struct {
	ClusterID   int64  `json:"cluster_id"`
	MessageText string `json:"message_text"`
}

// LogOrigins struct.
type LogOrigins struct {
	SenderBinary string `json:"sender_binary"`
	SenderFile   string `json:"sender_file"`
	SenderLine   int64  `json:"sender_line"`
	SenderPid    int64  `json:"sender_pid"`
	TvNsec       int64  `json:"tv_nsec"`
	TvSec        int64  `json:"tv_sec"`
}

func (a *Log) Copy() *Log {
	return &Log{
		LogId:    a.LogId,
		LogClass: a.LogClass,
		Created:  a.Created,
		Severity: a.Severity,

		LogSpecifics: a.LogSpecifics,
		// LogOrigins:   a.LogOrigins,
	}
}
