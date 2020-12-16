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
	WithHosts bool      `json:"with_hosts,omitempty"`
	Filters   []*Filter `json:"filters"`
}

type ClusterListReply struct {
	Clusters    []*ClusterExt                `json:"clusters"`
	LastUpdated map[string]*cmonapi.NullTime `json:"last_updated"`
}
