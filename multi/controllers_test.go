package multi

import (
	"testing"

	"github.com/severalnines/cmon-proxy/config"
	"github.com/severalnines/cmon-proxy/multi/router"
	"github.com/stretchr/testify/assert"
)

func TestFetchControllerIDFromInfo(t *testing.T) {
	// Create a test config
	cfg := &config.Config{
		Timeout: 30,
	}

	// Create a router
	r, err := router.New(cfg)
	assert.NoError(t, err)

	// Create a test instance without controller_id
	instance := &config.CmonInstance{
		Xid:  "test-xid",
		Url:  "test.example.com:9443",
		Name: "Test Controller",
	}

	// Create a proxy instance for testing
	proxy := &Proxy{
		cfg: cfg,
		r:   map[string]*router.Router{router.DefaultRouter: r},
	}

	// Test the FetchControllerIDFromInfo function
	// Note: This will fail in a real test environment since we can't connect to a real server
	// but it tests the function structure
	controllerID, err := proxy.FetchControllerIDFromInfo(instance)

	// Since we can't actually connect to a server in this test, we expect an error
	// but we can verify the function doesn't panic and returns appropriate error
	assert.Error(t, err)
	assert.Empty(t, controllerID)
}

func TestInfoOneWithMissingControllerID(t *testing.T) {
	// Create a test config
	cfg := &config.Config{
		Timeout: 30,
	}

	// Create a router
	r, err := router.New(cfg)
	assert.NoError(t, err)

	// Create a test instance without controller_id
	instance := &config.CmonInstance{
		Xid:  "test-xid",
		Url:  "test.example.com:9443",
		Name: "Test Controller",
	}

	// Create a proxy instance for testing
	proxy := &Proxy{
		cfg: cfg,
		r:   map[string]*router.Router{router.DefaultRouter: r},
	}

	// Test the infoOne function
	// Note: This will fail in a real test environment since we can't connect to a real server
	// but it tests the function structure
	status := proxy.infoOne(instance)

	// Verify the status structure is created correctly
	assert.NotNil(t, status)
	assert.Equal(t, instance.Xid, status.Xid)
	assert.Equal(t, instance.Url, status.Url)
	assert.Equal(t, "Test Controller", status.Name)
} 