package cmon

import (
	"fmt"

	"github.com/severalnines/cmon-proxy/cmon/api"
)

func (client *Client) CreateAccount(req *api.CreateAccountRequest) (*api.CreateAccountResponse, error) {
	req.Operation = "createAccount"
	if err := api.CheckClusterID(req); err != nil {
		return nil, err
	}
	res := &api.CreateAccountResponse{}
	if err := client.Request(api.ModuleClusters, req, res); err != nil {
		return nil, err
	}
	if res.RequestStatus != api.RequestStatusOk {
		return nil, api.NewErrorFromResponseData(res.WithResponseData)
	}
	return res, nil
}

func (client *Client) ListAccounts(req *api.ListAccountsRequest) (*api.ListAccountsResponse, error) {
	req.Operation = "getAccounts"
	if req.WithClusterID == nil || req.WithClusterID.ClusterID < 1 {
		return nil, fmt.Errorf("invalid cluster id")
	}
	res := &api.ListAccountsResponse{}
	if err := client.Request(api.ModuleClusters, req, res); err != nil {
		return nil, err
	}
	if res.RequestStatus != api.RequestStatusOk {
		return nil, api.NewErrorFromResponseData(res.WithResponseData)
	}
	return res, nil
}

func (client *Client) DeleteAccount(req *api.DeleteAccountRequest) (*api.DeleteAccountResponse, error) {
	req.Operation = "deleteAccount"
	if req.WithClusterID == nil || req.WithClusterID.ClusterID < 1 {
		return nil, fmt.Errorf("invalid cluster id")
	}
	if req.Account == nil {
		return nil, fmt.Errorf("account is nil")
	}
	if req.Account.UserName == "" {
		return nil, fmt.Errorf("invalid/empty username")
	}
	res := &api.DeleteAccountResponse{}
	if err := client.Request(api.ModuleClusters, req, res); err != nil {
		return nil, err
	}
	if res.RequestStatus != api.RequestStatusOk {
		return nil, api.NewErrorFromResponseData(res.WithResponseData)
	}
	return res, nil
}
