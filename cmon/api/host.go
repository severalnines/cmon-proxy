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

// Host struct.
type Host struct {
	*WithClassName `json:",inline"`

	Acl                   string            `json:"acl"`
	CdtPath               string            `json:"cdt_path"`
	ClusterID             CmonInt           `json:"clusterid"`
	Connected             bool              `json:"connected"`
	Container             bool              `json:"container"`
	Datadir               string            `json:"datadir"`
	Distribution          *Distribution     `json:"distribution"`
	HostID                uint64            `json:"hostId"`
	Hostname              string            `json:"hostname"`
	HostnameData          string            `json:"hostname_data"`
	HostnameInternal      string            `json:"hostname_internal"`
	HostStatus            string            `json:"hoststatus"`
	IP                    string            `json:"ip"`
	LastSeen              int64             `json:"lastseen"`
	ListeningPort         CmonInt           `json:"listening_port"`
	LogBin                string            `json:"log_bin"`
	LogBinBasename        string            `json:"log_bin_basename"`
	Logfile               string            `json:"logfile"`
	MaintenanceMode       string            `json:"maintenance_mode"`
	MaintenanceModeActive bool              `json:"maintenance_mode_active"`
	Message               string            `json:"message"`
	Nodetype              string            `json:"nodetype"`
	PerformanceSchema     bool              `json:"performance_schema"`
	Pid                   int64             `json:"pid,omitempty"`
	Pidfile               string            `json:"pidfile,omitempty"`
	Pingstatus            int               `json:"pingstatus,omitempty"`
	Pingtime              int64             `json:"pingtime,omitempty"`
	Port                  CmonInt           `json:"port"`
	Readonly              bool              `json:"readonly"`
	ReplicationSlave      *ReplicationSlave `json:"replication_slave,omitempty"`
	Role                  string            `json:"role"`
	ROPort                CmonInt           `json:"ro_port"`
	RWPort                CmonInt           `json:"rw_port"`
	ServiceStarted        int64             `json:"service_started"`
	SSLCerts              *SSLCerts         `json:"ssl_certs"`
	StoppedAt             string            `json:"stopped_at"`
	UniqueID              uint64            `json:"unique_id"`
	Uptime                int64             `json:"uptime"`

	// mssql
	Replica *MssqlReplica `json:"replica"`

	// postgres
	ReplicationState string `json:"replication_state,omitempty"`
}

// IsSSLEnabled returns true if ssl is enabled on this host.
func (h *Host) IsSSLEnabled() bool {
	return h.SSLCerts != nil &&
		h.SSLCerts.Server != nil &&
		h.SSLCerts.Server.SSLEnabled == true
}

// SSLCerts struct.
type SSLCerts struct {
	Replication *SSLCert `json:"replication"`
	Server      *SSLCert `json:"server"`
}

// SSLCert struct.
type SSLCert struct {
	CA         string `json:"ca"`
	ID         int64  `json:"id"`
	Key        string `json:"key"`
	Path       string `json:"path"`
	SSLEnabled bool   `json:"ssl_enabled"`
}

// Distribution struct.
type Distribution struct {
	Codename string `json:"codename"`
	Name     string `json:"name"`
	Release  string `json:"release"`
	Type     string `json:"type"`
}

// ReplicationSlave struct.
type ReplicationSlave struct {
	MasterClusterId     CmonInt `json:"master_cluster_id,omitempty"`
	MasterHost          string  `json:"master_host,omitempty"`
	MasterPort          string  `json:"master_port,omitempty"`
	PrevMasterHost      string  `json:"prev_master_host,omitempty"`
	PrevMasterPort      string  `json:"prev_master_port,omitempty"`
	SecondsBehindMaster CmonInt `json:"seconds_behind_master,omitempty"`

	// redis
	Status string `json:"status,omitempty"`

	// mysql
	SlaveIoRunning  string `json:"slave_io_running,omitempty"`
	SlaveSqlRunning string `json:"slave_sql_running,omitempty"`
}

type MssqlReplica struct {
	SynchronizationHealth string `json:"synchronization_health,omitempty"`
}
