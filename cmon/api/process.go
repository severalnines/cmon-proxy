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
	"time"
)

type GetSqlProcessesRequest struct {
	*WithOperation `json:",inline"`
	*WithClusterID `json:",inline"`
	*WithLimit     `json:",inline"`
}

type GetSqlProcessesResponse struct {
	*WithControllerID `json:",inline"`
	*WithResponseData `json:",inline"`

	Processes []*SQLProcess `json:"processes"`
}

type SQLProcess struct {
	BlockedByTrxID string `json:"blocked_by_trx_id"`
	Client         string `json:"client"`
	Command        string `json:"command"`
	CurrentTime    int64  `json:"currentTime"`
	DB             string `json:"db"`
	Duration       int64  `json:"duration"`
	Host           string `json:"host"`
	HostID         uint64 `json:"host_id"`
	Hostname       string `json:"hostname"`
	Info           string `json:"info"`
	InnodbStatus   string `json:"innodb_status"`
	InnodbTrxID    string `json:"innodb_trx_id"`
	Instance       string `json:"instance"`
	Lastseen       int64  `json:"lastseen"`
	Message        string `json:"message"`
	MysqlTrxID     int64  `json:"mysql_trx_id"`
	PID            int64  `json:"pid"`
	Query          string `json:"query"`
	ReportTS       int64  `json:"report_ts"`
	SQL            string `json:"sql"`
	State          string `json:"state"`
	Time           int64  `json:"time"`
	User           string `json:"user"`
	UserName       string `json:"userName"`
	ElapsedTime    string `json:"elapsedTime"`
}

// GetInstance returns SQLProcess.Instance || SQLProcess.Hostname || "unknown"
func (pl *SQLProcess) GetInstance() string {
	if pl.Instance != "" {
		return pl.Instance
	}
	if pl.Hostname != "" {
		return pl.Hostname
	}
	return "unknown"
}

// GetQueryTime returns SQLProcess.Time || SQLProcess.ElapsedTime || 0
func (pl *SQLProcess) GetQueryTime() int64 {
	if pl.Time > 0 {
		return pl.Time
	}
	if pl.ElapsedTime != "" {
		if t, err := time.Parse("15:04:05.000000", pl.ElapsedTime); err == nil {
			return int64(t.Sub(qt).Seconds())
		}
	}
	return 0
}

// GetUser returns SQLProcess.User || SQLProcess.UserName || ""
func (pl *SQLProcess) GetUser() string {
	if pl.User != "" {
		return pl.User
	}
	if pl.UserName != "" {
		return pl.UserName
	}
	return ""
}

type GetTopQueriesRequest struct {
	*WithOperation `json:",inline"`
	*WithClusterID `json:",inline"`
	*WithLimit     `json:",inline"`
}

type GetTopQueriesResponse struct {
	*WithResponseData `json:",inline"`
	*WithTotal        `json:",inline"`

	Digest []*TopQuery `json:"digests"`
}

type TopQuery struct {
	*WithClassName `json:",inline"`

	AffectedRows     int64     `json:"affectedRows"`
	Count            int64     `json:"count"`
	DatabaseName     string    `json:"databaseName"`
	DtFirstSeen      time.Time `json:"dtFirstSeen"`
	DtLastSeen       time.Time `json:"dtLastSeen"`
	Instance         string    `json:"instance"`
	StatementPattern string    `json:"statementPattern"`
	WaitMillisMax    float64   `json:"waitMillisMax"`
	WaitMillisMin    float64   `json:"waitMillisMin"`
	WaitMillisSum    float64   `json:"waitMillisSum"`
	WaitMillisAvg    float64   `json:"waitMillisAvg"`
}
