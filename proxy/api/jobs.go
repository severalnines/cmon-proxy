package api

import (
	"github.com/severalnines/cmon-proxy/cmon/api"
	cmonapi "github.com/severalnines/cmon-proxy/cmon/api"
)

type JobsStatus struct {
	// Job counts by job status
	JobCounts map[string]int `json:"job_count"`
	// Job counts by job commands
	JobCommands map[string]int `json:"job_commands"`

	// Job counts by controller
	JobCountsByController map[string]*JobsStatus `json:"by_controller,omitempty"`

	// for the "technology" filters
	ByClusterType map[string]*JobsStatus `json:"by_cluster_type,omitempty"`
}

// JobExt is a cmon Job extended by controller ID / URL fields
type JobExt struct {
	*WithControllerID
	*api.Job
}

type JobListRequest struct {
	ListRequest `json:",inline"`
	//	LastNHours  int `json:"last_n_hours"`
}

type JobListReply struct {
	ListResponse `json:",inline"`
	Jobs         []*JobExt                    `json:"jobs"`
	LastUpdated  map[string]*cmonapi.NullTime `json:"last_updated"`
}
