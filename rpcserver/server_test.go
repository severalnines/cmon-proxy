package rpcserver

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/severalnines/cmon-proxy/config"
)

func TestStart(t *testing.T) {
	// make sure HTTP server gets stopped at the end
	defer Stop()

	// some preps to accept self-signed certs
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	testUser := &config.ProxyUser{
		Username:     "testuser",
		EmailAddress: "test@s9s.io",
	}
	testUser.SetPassword("password")

	testConfig := &config.Config{
		Instances: []*config.CmonInstance{
			&config.CmonInstance{
				Url:     "https://127.0.0.1:9501",
				Name:    "dummy",
				UseLdap: true,
			},
		},
		Port:    10999,
		TlsCert: "./testcert.crt",
		TlsKey:  "./testcert.key",
		Users:   []*config.ProxyUser{testUser},
	}

	t.Run("testStartStop", func(t *testing.T) {
		// start in a goroutine as it wont return till it stops
		go Start(testConfig)
		for i := 0; i < 60; i++ {
			time.Sleep(500 * time.Millisecond)
			if httpServer == nil {
				continue
			}
			// keep try connection attempts until the service is up
			_, err := http.Get(fmt.Sprintf("https://127.0.0.1:%d", testConfig.Port))
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
}
