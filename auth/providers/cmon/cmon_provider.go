package cmon

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/severalnines/cmon-proxy/auth/user"
	"go.uber.org/zap"
)

type Provider struct {
	whoamiURL string
	client    *http.Client
	logger    *zap.SugaredLogger
}

func NewProvider(whoamiURL string, client *http.Client) *Provider {
	return &Provider{
		whoamiURL: whoamiURL,
		client:    client,
		logger:    zap.L().Sugar(),
	}
}

func (p *Provider) GetUserInfo(authCtx *user.AuthContext) (*user.User, error) {
	if authCtx.Request == nil {
		return nil, fmt.Errorf("HTTP request is required for CMON provider")
	}

	cmonSIDCookie, err := authCtx.Request.Cookie("cmon-sid")
	if err != nil {
		return nil, fmt.Errorf("cmon-sid cookie not found in request: %v", err)
	}

	payload := map[string]string{"operation": "whoAmI"}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", p.whoamiURL, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "cmon-sid", Value: cmonSIDCookie.Value})

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("whoami request failed with status: %d", resp.StatusCode)
	}

	var userResp struct {
		User struct {
			UserName string `json:"user_name"`
			Groups   []struct {
				GroupName string `json:"group_name"`
			} `json:"groups"`
		} `json:"user"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&userResp); err != nil {
		return nil, err
	}

	roles := make([]string, len(userResp.User.Groups))
	for i, group := range userResp.User.Groups {
		roles[i] = group.GroupName
	}

	return &user.User{
		UserName: userResp.User.UserName,
		Roles:    roles,
	}, nil
}
