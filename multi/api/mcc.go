package api

import cmonapi "github.com/severalnines/cmon-proxy/cmon/api"

type EnableMccRequest struct {
	User        *UserWithPassword `json:"user,omitempty"`
	LdapEnabled bool              `json:"ldap_enabled,omitempty"`
}

type EnableMccResponse struct {
	*cmonapi.WithResponseData `json:",inline"`
	Enable                    bool `json:"enable"`
}
