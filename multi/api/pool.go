package api

import cmonapi "github.com/severalnines/cmon-proxy/cmon/api"

type SetPoolVisibleRequest struct {
	Visible bool `json:"visible"`
}

type SetPoolVisibleResponse struct {
	*cmonapi.WithResponseData `json:",inline"`
}

