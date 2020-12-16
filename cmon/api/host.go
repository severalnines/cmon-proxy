package api

// Host struct.
type Host struct {
	*WithClassName `json:",inline"`

	ClusterID      CmonInt   `json:"clusterid"`
	ServiceStarted int64     `json:"service_started"`
	HostID         uint64    `json:"hostId"`
	UniqueID       uint64    `json:"unique_id"`
	LastSeen       int64     `json:"lastseen"`
	Port           CmonInt   `json:"port"`
	ListeningPort  CmonInt   `json:"listening_port"`
	Hostname       string    `json:"hostname"`
	HostStatus     string    `json:"hoststatus"`
	Role           string    `json:"role"`
	Nodetype       string    `json:"nodetype"`
	IP             string    `json:"ip"`
	RWPort         CmonInt   `json:"rw_port"`
	ROPort         CmonInt   `json:"ro_port"`
	Uptime         int64     `json:"uptime"`
	SSLCerts       *SSLCerts `json:"ssl_certs"`
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
