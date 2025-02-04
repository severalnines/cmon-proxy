package k8s_proxy_client

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/severalnines/cmon-proxy/config"
)

const (
	tokenCacheKey  = "k8s_proxy_jwt_token"
	tokenExpireKey = "k8s_proxy_jwt_expire"
)

type K8sProxyClient struct {
	httpClient *http.Client
	cfg        *config.Config
}

func NewK8sProxyClient(cfg *config.Config) *K8sProxyClient {
	return &K8sProxyClient{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: time.Second * 10,
		},
	}
}

func (c *K8sProxyClient) getJWTToken(cmonSID string) (string, error) {
	log.Printf("Requesting JWT token from auth service: %s", c.cfg.AuthServiceURL)
	req, err := http.NewRequest("POST", c.cfg.AuthServiceURL, nil)
	if err != nil {
		log.Printf("Error creating request for JWT token: %v", err)
		return "", err
	}

	req.Header.Set("Cookie", fmt.Sprintf("cmon-sid=%s", cmonSID))
	log.Printf("Sending request to auth service with cmon-sid: %s", cmonSID)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		log.Printf("Error sending request to auth service: %v", err)
		return "", err
	}
	defer resp.Body.Close()

	log.Printf("Auth service response status: %d", resp.StatusCode)
	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		log.Printf("Auth service error response body: %s", string(body))
		return "", fmt.Errorf("auth service returned status: %d", resp.StatusCode)
	}

	var result struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Printf("Error decoding auth service response: %v", err)
		return "", err
	}

	log.Printf("Successfully obtained JWT token")
	return result.Token, nil
}

func (c *K8sProxyClient) ProxyRequest(ctx *gin.Context, path string) {
	log.Printf("Received request to proxy: %s %s", ctx.Request.Method, path)

	// Check if this is an SSE request
	isSSE := ctx.GetHeader("Accept") == "text/event-stream"
	if isSSE {
		c.handleSSERequest(ctx, path)
		return
	}

	sess := sessions.Default(ctx)

	cmonSID, err := ctx.Cookie("cmon-sid")
	if err != nil {
		log.Printf("Error getting cmon-sid cookie: %v", err)
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Missing cmon-sid cookie"})
		return
	}
	log.Printf("Found cmon-sid cookie: %s", cmonSID)

	// Check if we have a cached token
	var token string
	cachedToken := sess.Get(tokenCacheKey)
	cachedExpire := sess.Get(tokenExpireKey)
	if cachedToken != nil && cachedExpire != nil {
		expireTime := cachedExpire.(int64)
		if time.Now().Unix() < expireTime {
			token = cachedToken.(string)
			log.Printf("Using cached JWT token, expires at: %v", time.Unix(expireTime, 0))
		}
	}

	// If no valid cached token, get a new one
	if token == "" {
		log.Printf("No valid cached token, requesting new JWT token")
		var err error
		token, err = c.getJWTToken(cmonSID)
		if err != nil {
			log.Printf("Failed to get JWT token: %v", err)
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get JWT token"})
			return
		}

		// Cache the token for 1 minute
		expireTime := time.Now().Add(time.Minute).Unix()
		sess.Set(tokenCacheKey, token)
		sess.Set(tokenExpireKey, expireTime)
		if err := sess.Save(); err != nil {
			log.Printf("Failed to save session: %v", err)
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save session"})
			return
		}
		log.Printf("New JWT token cached, expires at: %v", time.Unix(expireTime, 0))
	}

	// Proxy the request to k8s-proxy
	proxyURL := c.cfg.K8sProxyURL + path
	log.Printf("Proxying request to: %s %s", ctx.Request.Method, proxyURL)

	// Create a new URL with the base proxyURL
	parsedURL, err := url.Parse(proxyURL)
	if err != nil {
		log.Printf("Failed to parse proxy URL: %v", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create proxy request"})
		return
	}

	// Copy the query parameters from the original request
	parsedURL.RawQuery = ctx.Request.URL.RawQuery

	req, err := http.NewRequest(ctx.Request.Method, parsedURL.String(), ctx.Request.Body)
	if err != nil {
		log.Printf("Failed to create proxy request: %v", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create proxy request"})
		return
	}

	req.Header.Set("Authorization", "Bearer "+token)
	log.Printf("Set Authorization header with Bearer token")

	// Copy all headers from the original request
	for name, values := range ctx.Request.Header {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	log.Printf("Copied all headers from original request")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		log.Printf("Failed to send proxy request: %v", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to proxy request"})
		return
	}
	defer resp.Body.Close()

	log.Printf("Received response from k8s-proxy with status: %d", resp.StatusCode)

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Failed to read proxy response body: %v", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read proxy response"})
		return
	}

	log.Printf("Response body length: %d bytes", len(body))

	// Copy headers from the proxy response to the client response
	for name, values := range resp.Header {
		for _, value := range values {
			ctx.Header(name, value)
		}
	}
	log.Printf("Copied all headers from proxy response")

	ctx.Data(resp.StatusCode, resp.Header.Get("Content-Type"), body)
	log.Printf("Sent response to client with status: %d", resp.StatusCode)
}

func (c *K8sProxyClient) handleSSERequest(ctx *gin.Context, path string) {
	// Set SSE headers
	ctx.Header("Content-Type", "text/event-stream")
	ctx.Header("Cache-Control", "no-cache")
	ctx.Header("Connection", "keep-alive")
	ctx.Header("Transfer-Encoding", "chunked")

	// Get auth token as before
	cmonSID, err := ctx.Cookie("cmon-sid")
	if err != nil {
		log.Printf("Error getting cmon-sid cookie: %v", err)
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Missing cmon-sid cookie"})
		return
	}

	token, err := c.getJWTToken(cmonSID)
	if err != nil {
		log.Printf("Failed to get JWT token: %v", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get JWT token"})
		return
	}

	// Create proxy request
	proxyURL := c.cfg.K8sProxyURL + path
	req, err := http.NewRequest(ctx.Request.Method, proxyURL, nil)
	if err != nil {
		log.Printf("Failed to create proxy request: %v", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create proxy request"})
		return
	}

	// Set headers
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Connection", "keep-alive")

	// Copy query parameters
	req.URL.RawQuery = ctx.Request.URL.RawQuery

	// Use a client with no timeout for SSE
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Failed to send proxy request: %v", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to proxy request"})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Proxy request failed with status: %d", resp.StatusCode)
		ctx.JSON(resp.StatusCode, gin.H{"error": "Proxy request failed"})
		return
	}

	// Create a reader for the response body
	reader := bufio.NewReader(resp.Body)

	// Stream the response
	ctx.Stream(func(w io.Writer) bool {
		// Read each line
		line, err := reader.ReadBytes('\n')
		if err != nil {
			if err != io.EOF {
				log.Printf("Error reading from proxy response: %v", err)
			}
			return false
		}

		log.Printf("Proxying SSE event: %s", string(line))
		// Write the line to the client
		_, err = w.Write(line)
		if err != nil {
			log.Printf("Error writing to client: %v", err)
			return false
		}
		return true
	})
}
