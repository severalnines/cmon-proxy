package api

import (
	cmonapi "github.com/severalnines/cmon-proxy/cmon/api"
)

// ClusterExt is a cmon cluster extended by controller ID / URL fields
type ClusterExt struct {
	*WithControllerID
	*cmonapi.Cluster
}

type ClusterListRequest struct {
	ListRequest `json:",inline"`
	WithHosts   bool `json:"with_hosts,omitempty"`
}

type ClusterListReply struct {
	ListResponse `json:",inline"`
	Clusters     []*ClusterExt                `json:"clusters"`
	LastUpdated  map[string]*cmonapi.NullTime `json:"last_updated"`
}
