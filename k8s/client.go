package k8s_proxy_client

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	auth "github.com/severalnines/cmon-proxy/auth"
	"github.com/severalnines/cmon-proxy/auth/providers/cmon"
	"github.com/severalnines/cmon-proxy/auth/providers/cmonproxy"
	"github.com/severalnines/cmon-proxy/auth/user"
	"github.com/severalnines/cmon-proxy/config"
	"go.uber.org/zap"
)

const (
	tokenCacheKey  = "k8s_proxy_jwt_token"
	tokenExpireKey = "k8s_proxy_jwt_expire"
)

type K8sProxyClient struct {
	httpClient *http.Client
	cfg        *config.Config
	auth       *auth.Auth
	logger     *zap.SugaredLogger
}

func NewK8sProxyClient(cfg *config.Config) (*K8sProxyClient, error) {
	client := &K8sProxyClient{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: time.Second * 10,
		},
		logger: zap.L().Sugar(),
	}

	err := client.InitAuthService(cfg)
	if err != nil {
		return nil, err
	}

	return client, nil
}

func (c *K8sProxyClient) InitAuthService(cfg *config.Config) error {
	// Create a custom HTTP client for providers that ignores certificate issues
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	providerClient := &http.Client{Transport: tr}

	// Get or generate JWT secret
	secret, err := cfg.GetJWTSecret()
	if err != nil {
		return fmt.Errorf("failed to get JWT secret: %v", err)
	}

	// Initialize auth service with appropriate provider
	var userProvider user.Provider

	var singleControllerInstance *config.CmonInstance
	if cfg.SingleController != "" {
		for _, instance := range cfg.Instances {
			if instance.Xid == cfg.SingleController {
				singleControllerInstance = instance
				break
			}
		}
	}

	// Use CmonProxy provider if SingleController is not set
	if singleControllerInstance == nil && cfg.Port != 0 {
		baseURL := fmt.Sprintf("https://127.0.0.1:%d", cfg.Port)
		userProvider = cmonproxy.NewProvider(baseURL, providerClient)
		c.logger.Infof("Using CmonProxy user provider with URL: %s", baseURL)
	} else if singleControllerInstance != nil && singleControllerInstance.Url != "" {
		// Use CMON provider if WhoamiURL is set
		var whoamiURL string = "https://" + singleControllerInstance.Url + "/v2/users"
		userProvider = cmon.NewProvider(whoamiURL, providerClient)
		c.logger.Infof("Using CMON user provider with WhoamiURL: %s", whoamiURL)
	} else {
		return fmt.Errorf("no valid user provider configuration found")
	}

	authOpts := auth.Options{
		JWTSecret: secret,
		Provider:  userProvider,
	}

	authService, err := auth.New(authOpts)
	if err != nil {
		return fmt.Errorf("failed to initialize auth service: %v", err)
	}
	c.auth = authService

	return nil
}

func (c *K8sProxyClient) getJWTToken(ctx *gin.Context) (string, error) {
	// Use the auth service to generate token from the request
	if c.auth != nil {
		return c.auth.GenerateToken(ctx.Request)
	}

	return "", fmt.Errorf("auth service not initialized")
}

func (c *K8sProxyClient) ProxyRequest(ctx *gin.Context, path string) {
	isSSE := ctx.GetHeader("Accept") == "text/event-stream"
	if isSSE {
		c.handleSSERequest(ctx, path)
		return
	}

	sess := sessions.Default(ctx)

	// Check if we have a valid cached token
	var token string
	cachedToken := sess.Get(tokenCacheKey)
	cachedExpire := sess.Get(tokenExpireKey)
	if cachedToken != nil && cachedExpire != nil {
		expireTime := cachedExpire.(int64)
		if time.Now().Unix() < expireTime {
			token = cachedToken.(string)
		}
	}

	// If no valid cached token, get a new one and cache it
	if token == "" {
		var err error
		token, err = c.getJWTToken(ctx)
		if err != nil {
			c.logger.Errorf("Failed to get JWT token: %v", err)
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get JWT token"})
			return
		}

		// Cache the token for 1 minute
		expireTime := time.Now().Add(time.Minute).Unix()
		sess.Set(tokenCacheKey, token)
		sess.Set(tokenExpireKey, expireTime)
		if err := sess.Save(); err != nil {
			c.logger.Errorf("Failed to save session: %v", err)
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save session"})
			return
		}
	}

	proxyURL := c.cfg.K8sProxyURL + path

	parsedURL, err := url.Parse(proxyURL)
	if err != nil {
		c.logger.Errorf("Failed to parse proxy URL: %v", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create proxy request"})
		return
	}

	// Copy the query parameters from the original request
	parsedURL.RawQuery = ctx.Request.URL.RawQuery

	req, err := http.NewRequest(ctx.Request.Method, parsedURL.String(), ctx.Request.Body)
	if err != nil {
		c.logger.Errorf("Failed to create proxy request: %v", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create proxy request"})
		return
	}

	req.Header.Set("Authorization", "Bearer "+token)

	// Copy all headers from the original request
	for name, values := range ctx.Request.Header {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.logger.Errorf("Failed to send proxy request: %v", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to proxy request"})
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		c.logger.Errorf("Failed to read proxy response body: %v", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read proxy response"})
		return
	}

	// Copy headers from the proxy response to the client response
	for name, values := range resp.Header {
		for _, value := range values {
			ctx.Header(name, value)
		}
	}
	ctx.Data(resp.StatusCode, resp.Header.Get("Content-Type"), body)
}

func (c *K8sProxyClient) handleSSERequest(ctx *gin.Context, path string) {
	// Set SSE headers for the client response
	ctx.Header("Content-Type", "text/event-stream")
	ctx.Header("Cache-Control", "no-cache")
	ctx.Header("Connection", "keep-alive")
	ctx.Header("Transfer-Encoding", "chunked")

	token, err := c.getJWTToken(ctx)
	if err != nil {
		c.logger.Errorf("Failed to get JWT token: %v", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get JWT token"})
		return
	}

	proxyURL := c.cfg.K8sProxyURL + path
	req, err := http.NewRequest(ctx.Request.Method, proxyURL, nil)
	if err != nil {
		c.logger.Errorf("Failed to create proxy request: %v", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create proxy request"})
		return
	}

	// Set headers for the backend request
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Connection", "keep-alive")

	req.URL.RawQuery = ctx.Request.URL.RawQuery

	// Use a client with no timeout for potentially long-lived SSE streams
	sseClient := &http.Client{}
	resp, err := sseClient.Do(req)
	if err != nil {
		c.logger.Errorf("Failed to send SSE proxy request: %v", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to proxy SSE request"})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		c.logger.Errorf("SSE proxy request failed with status: %d, Body: %s", resp.StatusCode, string(bodyBytes))
		ctx.JSON(resp.StatusCode, gin.H{"error": "Proxy request failed", "details": string(bodyBytes)})
		return
	}

	reader := bufio.NewReader(resp.Body)

	// Stream the response line by line
	ctx.Stream(func(w io.Writer) bool {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			if err != io.EOF {
				// Log errors during streaming but continue trying if possible
				c.logger.Errorf("Error reading from SSE proxy response: %v", err)
			}
			// Stop streaming if EOF or other read error occurs
			return false
		}

		_, err = w.Write(line)
		if err != nil {
			// Client connection likely closed
			c.logger.Warnf("Error writing SSE data to client: %v", err)
			return false // Stop streaming
		}
		// Flush data to the client
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		return true // Continue streaming
	})
}
