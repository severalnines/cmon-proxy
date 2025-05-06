package api

import cmonapi "github.com/severalnines/cmon-proxy/cmon/api"

type EnableK8sRequest struct {
	Enable bool `json:"enable"`
}

type EnableK8sResponse struct {
	*cmonapi.WithResponseData `json:",inline"`
}
