package api

import (
	"github.com/severalnines/ccx/go/helpers"
)

type GetClusterInfoRequest struct {
	*WithOperation `json:",inline"`
	*WithClusterID `json:",inline"`

	WithHosts        bool `json:"with_hosts,omitempty"`
	WithSheetInfo    bool `json:"with_sheet_info,omitempty"`
	WithDatabases    bool `json:"with_databases,omitempty"`
	WithLicenseCheck bool `json:"with_license_check,omitempty"`
	WithTags         bool `json:"with_tags,omitempty"`
}

type GetClusterInfoResponse struct {
	*WithResponseData `json:",inline"`

	Cluster *Cluster `json:"cluster"`
}

type GetAllClusterInfoRequest struct {
	*WithOperation `json:",inline"`

	WithHosts        bool `json:"with_hosts,omitempty"`
	WithSheetInfo    bool `json:"with_sheet_info,omitempty"`
	WithDatabases    bool `json:"with_databases,omitempty"`
	WithLicenseCheck bool `json:"with_license_check,omitempty"`
	WithTags         bool `json:"with_tags,omitempty"`
}

type GetAllClusterInfoResponse struct {
	*WithResponseData `json:",inline"`
	*WithTotal        `json:",inline"`

	Clusters []*Cluster
}

type Cluster struct {
	*WithClassName `json:",inline"`

	ClusterID             uint64      `json:"cluster_id"`
	ClusterName           string      `json:"cluster_name"`
	ClusterType           string      `json:"cluster_type"`
	Databases             []*Database `json:"databases,omitempty"`
	Hosts                 []*Host     `json:"hosts"`
	State                 string      `json:"state"`
	MaintenanceModeActive bool        `json:"maintenance_mode_active"`
}

// IsSSLEnabled return true if all hosts in cluster have ssl_certs.server.ssl_enabled
// equal to true, return false otherwise. If hosts is nil or has 0 length - return false.
func (c *Cluster) IsSSLEnabled() bool {
	for _, h := range c.GetDatabaseHosts() {
		if !h.IsSSLEnabled() {
			return false
		}
	}
	return true
}

var (
	dbHostsClassNames = []string{
		"CmonPostgreSqlHost",
		"CmonGaleraHost",
	}
)

// GetDatabaseHosts returns a filtered list of hosts, containing only database hosts.
func (c *Cluster) GetDatabaseHosts() []*Host {
	list := make([]*Host, 0, len(c.Hosts))
	for _, h := range c.Hosts {
		if helpers.FindStr(dbHostsClassNames, h.ClassName) {
			list = append(list, h)
		}
	}
	return list
}

type CreateDatabaseRequest struct {
	*WithOperation `json:",inline"`
	*WithClusterID `json:",inline"`

	Database *Database `json:"database"`
}

type CreateDatabaseResponse struct {
	*WithResponseData `json:",inline"`

	Database *Database `json:"database"`
}

type ListDatabasesRequest struct {
	*WithOperation `json:",inline"`
	*WithClusterID `json:",inline"`
}

type ListDatabasesResponse struct {
	*WithResponseData `json:",inline"`

	Databases []*Database `json:"databases"`
}

type Database struct {
	*WithClassName `json:",inline"`

	Acl            string `json:"acl,omitempty"`
	CDTPath        string `json:"cdt_path,omitempty"`
	ClusterID      int64  `json:"cluster_id,omitempty"`
	DataDirectory  string `json:"data_directory,omitempty"`
	DatabaseID     int64  `json:"database_id,omitempty"`
	DatabaseName   string `json:"database_name,omitempty"`
	DatabaseSize   int64  `json:"database_size,omitempty"`
	Deleted        bool   `json:"deleted,omitempty"`
	Dirty          bool   `json:"dirty,omitempty"`
	Name           string `json:"name,omitempty"`
	NumberOfTables int64  `json:"number_of_tables,omitempty"`
	OwnerGroupID   int64  `json:"owner_group_id,omitempty"`
	OwnerGroupName string `json:"owner_group_name,omitempty"`
	OwnerUserID    int64  `json:"owner_user_id,omitempty"`
	OwnerUserName  string `json:"owner_user_name,omitempty"`
	Version        int64  `json:"version,omitempty"`
}
