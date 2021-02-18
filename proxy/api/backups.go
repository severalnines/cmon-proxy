package api

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
