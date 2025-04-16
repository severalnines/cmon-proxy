package cmonproxy

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/severalnines/cmon-proxy/auth/user"
	"github.com/severalnines/cmon-proxy/config"
	"go.uber.org/zap"
)

type Provider struct {
	baseURL string
	client  *http.Client
	logger  *zap.SugaredLogger
}

type authCheckResponse struct {
	User          *config.ProxyUser `json:"user"`
	RequestStatus string            `json:"request_status"`
	ErrorString   string            `json:"error_string"`
}

func NewProvider(baseURL string, client *http.Client) *Provider {
	return &Provider{
		baseURL: baseURL,
		client:  client,
		logger:  zap.L().Sugar(),
	}
}

func (p *Provider) GetUserInfo(authCtx *user.AuthContext) (*user.User, error) {
	if authCtx.Request == nil {
		return nil, fmt.Errorf("HTTP request is required for CmonProxy provider")
	}

	url := p.baseURL + "/proxy/auth/check"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	for _, cookie := range authCtx.Request.Cookies() {
		req.AddCookie(cookie)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("auth check request failed with status: %d", resp.StatusCode)
	}

	var authResp authCheckResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return nil, err
	}

	if authResp.RequestStatus != "Ok" {
		return nil, fmt.Errorf("authentication failed: %s", authResp.ErrorString)
	}

	if authResp.User == nil {
		return nil, fmt.Errorf("no user information in response")
	}

	return &user.User{
		UserName: authResp.User.Username,
		Roles:    authResp.User.Groups,
	}, nil
}
