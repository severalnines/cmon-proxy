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

	// Try to get cmon-sid from router first (if gin.Context is available and routerGetter is provided)
	if authCtx.Context != nil && p.routerGetter != nil {
		r := p.routerGetter(authCtx.Context)
		if r != nil {
			// Try to get CMONSid from router
			if r.CMONSid != nil {
				cmonSIDCookie = r.CMONSid
				p.logger.Debugf("Using cmon-sid from router")
			} else {
				// Try to get session cookie from router's client
				// Get the first available controller URL from router
				for _, addr := range r.Urls() {
					c := r.Cmon(addr)
					if c != nil && c.Client != nil {
						if sessionCookie := c.Client.GetSessionCookie(); sessionCookie != nil {
							cmonSIDCookie = sessionCookie
							p.logger.Debugf("Using cmon-sid from router client session")
							break
						}
					}
				}
			}
		}
	}

	// Fallback: try to read cmon-sid from request cookie
	if cmonSIDCookie == nil {
		cookie, err := authCtx.Request.Cookie("cmon-sid")
		if err != nil {
			return nil, fmt.Errorf("cmon-sid cookie not found in request and no router session available: %v", err)
		}
		cmonSIDCookie = cookie
		p.logger.Debugf("Using cmon-sid from request cookie")
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
