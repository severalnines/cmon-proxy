package cmon

import (
	"github.com/severalnines/cmon-proxy/cmon/api"
)

func (client *Client) Ping() (*api.PingResponse, error) {
	req := api.PingRequest{
		WithOperation:       &api.WithOperation{Operation: "ping"},
		WithClusterIDForced: &api.WithClusterIDForced{}}
	res := &api.PingResponse{}
	if err := client.Request(api.ModuleClusters, req, res, false); err != nil {
		return nil, err
	}
	if res.RequestStatus != api.RequestStatusOk {
		return nil, api.NewErrorFromResponseData(res.WithResponseData)
	}
	return res, nil
}
