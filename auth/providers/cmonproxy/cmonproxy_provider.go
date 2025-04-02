package cmonproxy

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/severalnines/cmon-proxy/auth/user"
	"github.com/severalnines/cmon-proxy/config"
	"go.uber.org/zap"
)

// Provider implements the user.Provider interface for CmonProxy
type Provider struct {
	baseURL string
	client  *http.Client
	logger  *zap.SugaredLogger
}

// Response from the /auth/check endpoint
type authCheckResponse struct {
	User          *config.ProxyUser `json:"user"`
	RequestStatus string            `json:"request_status"`
	ErrorString   string            `json:"error_string"`
}

// NewProvider creates a new CmonProxy user provider
func NewProvider(baseURL string, client *http.Client) *Provider {
	return &Provider{
		baseURL: baseURL,
		client:  client,
		logger:  zap.L().Sugar(),
	}
}

// GetUserInfo retrieves user information from CmonProxy /auth/check endpoint
func (p *Provider) GetUserInfo(authCtx *user.AuthContext) (*user.User, error) {
	if authCtx.Request == nil {
		return nil, fmt.Errorf("HTTP request is required for CmonProxy provider")
	}

	// Create a new request to the auth check endpoint
	url := p.baseURL + "/proxy/auth/check"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	// Copy all cookies from the original request
	for _, cookie := range authCtx.Request.Cookies() {
		req.AddCookie(cookie)
	}

	// Make the request
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("auth check request failed with status: %d", resp.StatusCode)
	}

	// Parse response
	var authResp authCheckResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return nil, err
	}

	// Check if authentication was successful
	if authResp.RequestStatus != "Ok" {
		return nil, fmt.Errorf("authentication failed: %s", authResp.ErrorString)
	}

	// Check if user information is available
	if authResp.User == nil {
		return nil, fmt.Errorf("no user information in response")
	}

	// Convert ProxyUser to user.User
	// Use Groups from ProxyUser as Roles
	return &user.User{
		UserName: authResp.User.Username,
		Roles:    authResp.User.Groups,
	}, nil
}
