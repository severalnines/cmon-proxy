package api

type ClustersOverview struct {
	// an overview of all clusters status (map key: status string)
	// for complete list see: https://github.com/severalnines/clustercontrol-enterprise/blob/master/src/cmoncluster.cpp#L3924
	ClusterStatus map[string]int `json:"cluster_states"`
	// clusters count by controller (map key: URL)
	ClustersCount map[string]int `json:"clusters_count"`
	NodesCount    map[string]int `json:"nodes_count,omitempty"`
	// the node states see:
	NodeStates map[string]int `json:"node_states,omitempty"`
}
