package api

import (
	"github.com/severalnines/cmon-proxy/cmon/api"
	cmonapi "github.com/severalnines/cmon-proxy/cmon/api"
)

// JobExt is a cmon Job extended by controller ID / URL fields
type JobExt struct {
	*WithControllerID
	*api.Job
}

type JobListRequest struct {
	ListRequest `json:",inline"`
	LastNHours  int `json:"last_n_hours"`
}

type JobListReply struct {
	ListResponse `json:",inline"`
	Jobs         []*JobExt                    `json:"clusters"`
	LastUpdated  map[string]*cmonapi.NullTime `json:"last_updated"`
}
