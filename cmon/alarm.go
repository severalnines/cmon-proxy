package cmon

import (
	"github.com/severalnines/cmon-proxy/cmon/api"
)

func (client *Client) GetAlarms(clusterId uint64) (*api.GetAlarmsReply, error) {
	req := &api.GetAlarmsRequest{
		WithOperation: &api.WithOperation{
			Operation: "getAlarms",
		},
		WithClusterID: &api.WithClusterID{
			ClusterID: clusterId,
		},
	}
	if err := api.CheckClusterID(req); err != nil {
		return nil, err
	}
	res := &api.GetAlarmsReply{}
	if err := client.Request(api.ModuleAlarm, req, res); err != nil {
		return nil, err
	}
	if res.RequestStatus != api.RequestStatusOk {
		return nil, api.NewErrorFromResponseData(res.WithResponseData)
	}
	return res, nil
}
