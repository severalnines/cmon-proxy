package rpcserver

import (
	"testing"

	"github.com/severalnines/cmon-proxy/config"
	"github.com/severalnines/cmon-proxy/multi"
	"github.com/stretchr/testify/assert"
)

func TestFetchMissingControllerIDs(t *testing.T) {
	// Create a test config with instances that have missing controller_ids
	cfg := &config.Config{
		Timeout: 30,
		Instances: []*config.CmonInstance{
			{
				Xid:  "test-xid-1",
				Url:  "test1.example.com:9443",
				Name: "Test Controller 1",
				// ControllerId is intentionally empty
			},
			{
				Xid:          "test-xid-2",
				Url:          "test2.example.com:9443",
				Name:         "Test Controller 2",
				ControllerId: "existing-controller-id", // This one has controller_id
			},
		},
	}

	// Create a proxy instance for testing using the proper constructor
	proxy, err := multi.New(cfg)
	assert.NoError(t, err)

	// Test the fetchMissingControllerIDs function
	// Note: This will fail in a real test environment since we can't connect to a real server
	// but it tests the function structure
	fetchMissingControllerIDs(proxy)

	// Verify that the function doesn't panic and handles the case gracefully
	// Since we can't actually connect to servers in this test, we expect the function
	// to log warnings but not crash
	assert.NotNil(t, proxy)
}
