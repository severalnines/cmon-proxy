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
	"github.com/severalnines/cmon-proxy/cmon/api"
	cmonapi "github.com/severalnines/cmon-proxy/cmon/api"
)

type BackupOverview struct {
	// Backup counts by severity
	BackupCounts map[string]int `json:"backups_count"`

	// Backup counts by controller
	BackupCountsByController map[string]*BackupOverview `json:"by_controller,omitempty"`

	// The number of clusters missing schedules
	MissingSchedules int `json:"missing_schedules"`

	// The number of schedules
	SchedulesCount int `json:"schedules_count"`

	// for the "technology" filters
	ByClusterType map[string]*BackupOverview `json:"by_cluster_type,omitempty"`
}

// BackupExt is a cmon Job extended by controller ID / URL fields
type BackupExt struct {
	*WithControllerID
	*api.Backup
}

type BackupListRequest struct {
	ListRequest `json:",inline"`
}

type BackupListReply struct {
	ListResponse `json:",inline"`
	Backups      []*BackupExt                 `json:"backups"`
	LastUpdated  map[string]*cmonapi.NullTime `json:"last_updated"`
}
