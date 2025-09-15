package rpcserver

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"testing"
	"time"

	cmonapi "github.com/severalnines/cmon-proxy/cmon/api"
	"github.com/severalnines/cmon-proxy/config"
	"github.com/severalnines/cmon-proxy/multi/api"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

func TestStart(t *testing.T) {
	t.Skip("it's broken")
	logger := zaptest.NewLogger(t)
	zap.ReplaceGlobals(logger)

	// make sure HTTP server gets stopped at the end
	defer Stop()

	// we need cookies and accept the self signed certs
	cookieJar, _ := cookiejar.New(nil)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true,
		ClientAuth:         tls.NoClientCert,
	}
	client := &http.Client{
		Jar:       cookieJar,
		Transport: transport,
	}

	testUser := &config.ProxyUser{
		Username:     "testuser",
		EmailAddress: "test@s9s.io",
	}
	testUser.SetPassword("password")

	testConfig := &config.Config{
		Instances: []*config.CmonInstance{
			{
				Url:  "https://127.0.0.1:9501",
				Name: "dummy",
			},
		},
		Port:    10999,
		TlsCert: "./testcert.crt",
		TlsKey:  "./testcert.key",
		Users:   []*config.ProxyUser{testUser},
	}

	baseUrl := fmt.Sprintf("https://127.0.0.1:%d", testConfig.Port)
	cookieUrl, _ := url.Parse(baseUrl)

	t.Run("testStartStop", func(t *testing.T) {
		// start in a goroutine as it wont return till it stops
		go Start(testConfig)
		defer Stop()

		for i := 0; i < 10; i++ {
			time.Sleep(500 * time.Millisecond)
			if httpServer == nil {
				continue
			}
			// keep try connection attempts until the service is up
			_, err := client.Get(baseUrl)
			if err != nil {
				continue
			}
			t.Log("rpc server is up & running")
			break
		}
		// lets stop now
		Stop()
		// and the server must be gone
		if httpServer != nil {
			t.FailNow()
		}
	})

	t.Run("testAuthenticate", func(t *testing.T) {
		// start in a goroutine as it wont return till it stops
		go Start(testConfig)
		defer Stop()

		for i := 0; i < 10; i++ {
			time.Sleep(500 * time.Millisecond)
			if httpServer == nil {
				continue
			}
			// keep try connection attempts until the service is up
			_, err := http.Get(baseUrl)
			if err != nil {
				continue
			}
			t.Log("rpc server is up & running")
			break
		}

		var loginResp api.LoginResponse
		/*
		 * Failed attempt
		 */
		login := &api.LoginRequest{
			Username: "testuser",
			Password: "invalid",
		}
		loginJson, _ := json.Marshal(login)
		req, _ := http.NewRequestWithContext(
			context.Background(), "POST", baseUrl+"/proxy/auth/login", bytes.NewReader(loginJson))
		resp, err := client.Do(req)
		if err != nil {
			t.Log("Error", err)
			t.FailNow()
		}
		respBody, _ := io.ReadAll(resp.Body)
		err = json.Unmarshal(respBody, &loginResp)
		if loginResp.RequestStatus != cmonapi.RequestStatusAccessDenied {
			j, _ := json.Marshal(loginResp)
			t.Log(string(j), "error:", err)
			t.Log("Got unexpected status after failed login:", loginResp.RequestStatus)
			t.Fail()
		}

		/*
		 * Success
		 */
		login = &api.LoginRequest{
			Username: "testuser",
			Password: "password",
		}
		loginJson, _ = json.Marshal(login)
		req, _ = http.NewRequestWithContext(
			context.Background(), "POST", baseUrl+"/proxy/auth/login", bytes.NewReader(loginJson))
		resp, err = client.Do(req)
		if err != nil {
			t.Log("Error", err)
			t.FailNow()
		}
		respBody, _ = io.ReadAll(resp.Body)
		err = json.Unmarshal(respBody, &loginResp)
		if loginResp.RequestStatus != cmonapi.RequestStatusOk {
			j, _ := json.Marshal(loginResp)
			t.Log(string(j), "error:", err)
			t.Log("Got unexpected status after login:", loginResp.RequestStatus)
			t.Fail()
		}
		// save cookies after successful auth
		client.Jar.SetCookies(cookieUrl, resp.Cookies())

		return

		/*
		 * Now check if we can query as authenticated user
		 */
		req, _ = http.NewRequestWithContext(
			context.Background(), "GET", baseUrl+"/proxy/controllers/status", nil)
		resp, err = client.Do(req)
		if err != nil {
			t.Log("Error", err)
			t.FailNow()
		}
		respBody, _ = io.ReadAll(resp.Body)
		err = json.Unmarshal(respBody, &loginResp)
		if loginResp.RequestStatus != cmonapi.RequestStatusOk {
			j, _ := json.Marshal(loginResp)
			t.Log(string(j), "error:", err)
			t.Log("Got unexpected status when listing controllers:", loginResp.RequestStatus)
			t.Fail()
		}
	})
}
