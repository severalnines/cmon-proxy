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


type ClustersOverview struct {
	// an overview of all clusters status (map key: status string)
	// for complete list see: https://github.com/severalnines/clustercontrol-enterprise/blob/master/src/cmoncluster.cpp#L3924
	ClusterStatus map[string]int `json:"cluster_states"`
	// clusters count by controller (map key: URL)
	ClustersCount map[string]int `json:"clusters_count"`
	NodesCount    map[string]int `json:"nodes_count,omitempty"`
	// the node states see:
	NodeStates map[string]int `json:"node_states,omitempty"`

	// for the "technology" filters
	ByClusterType map[string]*ClustersOverview `json:"by_cluster_type,omitempty"`
}
