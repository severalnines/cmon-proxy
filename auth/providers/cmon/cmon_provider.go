package cmon

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/severalnines/cmon-proxy/auth/user"
	"github.com/severalnines/cmon-proxy/multi/router"
	"go.uber.org/zap"
)

type Provider struct {
	whoamiURL    string
	client       *http.Client
	logger       *zap.SugaredLogger
	routerGetter func(*gin.Context) *router.Router // Optional function to get router from gin context
}

func NewProvider(whoamiURL string, client *http.Client, routerGetter ...func(*gin.Context) *router.Router) *Provider {
	var getter func(*gin.Context) *router.Router
	if len(routerGetter) > 0 {
		getter = routerGetter[0]
	}
	return &Provider{
		whoamiURL:    whoamiURL,
		client:       client,
		logger:       zap.L().Sugar(),
		routerGetter: getter,
	}
}

func (p *Provider) GetUserInfo(authCtx *user.AuthContext) (*user.User, error) {
	if authCtx.Request == nil {
		return nil, fmt.Errorf("HTTP request is required for CMON provider")
	}

	var cmonSIDCookie *http.Cookie

	// Get cmon-sid from router session (if gin.Context is available and routerGetter is provided)
	if authCtx.Context != nil && p.routerGetter != nil {
		r := p.routerGetter(authCtx.Context)
		if r != nil {
			// Try to get session cookie from router's client
			// Get the first available controller URL from router
			urls := r.Urls()
			p.logger.Debugf("Router has %d controller URLs", len(urls))
			for _, addr := range urls {
				c := r.Cmon(addr)
				if c != nil && c.Client != nil {
					if sessionCookie := c.Client.GetSessionCookie(); sessionCookie != nil {
						cmonSIDCookie = sessionCookie
						p.logger.Debugf("Using cmon-sid from router client session for controller %s", addr)
						break
					} else {
						p.logger.Debugf("No session cookie for controller %s", addr)
					}
				} else {
					if c == nil {
						p.logger.Debugf("No cmon client for controller %s", addr)
					} else {
						p.logger.Debugf("Client is nil for controller %s", addr)
					}
				}
			}
		} else {
			p.logger.Warnf("Router getter returned nil")
		}
	} else {
		if authCtx.Context == nil {
			p.logger.Warnf("Gin context is nil")
		}
		if p.routerGetter == nil {
			p.logger.Warnf("Router getter is nil")
		}
	}

	// No router session available
	if cmonSIDCookie == nil {
		return nil, fmt.Errorf("no router session available")
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
