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
}

type JobListReply struct {
	ListResponse `json:",inline"`
	Jobs         []*JobExt                    `json:"jobs"`
	LastUpdated  map[string]*cmonapi.NullTime `json:"last_updated"`
}
