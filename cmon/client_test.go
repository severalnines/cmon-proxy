package cmon

import (
	"testing"

	"github.com/severalnines/cmon-proxy/config"
	"github.com/stretchr/testify/assert"
)

func TestBuildURI(t *testing.T) {
	tests := []struct {
		name         string
		instanceURL  string
		module       string
		expectedPath string
	}{
		{
			name:         "URL without trailing slash",
			instanceURL:  "192.168.1.100/single",
			module:       "info",
			expectedPath: "/single/v2/info",
		},
		{
			name:         "URL with trailing slash",
			instanceURL:  "192.168.1.100/single/",
			module:       "info", 
			expectedPath: "/single/v2/info",
		},
		{
			name:         "URL with multiple trailing slashes",
			instanceURL:  "192.168.1.100/single///",
			module:       "info",
			expectedPath: "/single/v2/info",
		},
		{
			name:         "Root URL without trailing slash",
			instanceURL:  "192.168.1.100",
			module:       "ping",
			expectedPath: "/v2/ping",
		},
		{
			name:         "Root URL with trailing slash",
			instanceURL:  "192.168.1.100/",
			module:       "ping",
			expectedPath: "/v2/ping",
		},
		{
			name:         "Module with /v2 prefix and URL without trailing slash",
			instanceURL:  "192.168.1.100/single",
			module:       "/v2/clusters",
			expectedPath: "/single/v2/clusters",
		},
		{
			name:         "Module with /v2 prefix and URL with trailing slash",
			instanceURL:  "192.168.1.100/single/",
			module:       "/v2/clusters",
			expectedPath: "/single/v2/clusters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			instance := &config.CmonInstance{
				Url: tt.instanceURL,
			}
			client := &Client{
				Instance: instance,
			}

			result := client.buildURI(tt.module)
			assert.Contains(t, result, tt.expectedPath, "Expected path %s to be in URI %s", tt.expectedPath, result)
			
			// Ensure no double slashes in the path (except after protocol)
			// Remove the protocol part and check for double slashes
			protocolEnd := len("https://")
			if len(result) > protocolEnd {
				pathPart := result[protocolEnd:]
				// Find the first slash after the host to get the path
				if firstSlash := findHostEnd(pathPart); firstSlash != -1 {
					pathOnly := pathPart[firstSlash:]
					assert.NotContains(t, pathOnly, "//", "Path should not contain double slashes: %s", result)
				}
			}
		})
	}
}

// findHostEnd finds the end of the host part in a URL path (first slash after host)
func findHostEnd(pathPart string) int {
	for i, char := range pathPart {
		if char == '/' {
			return i
		}
	}
	return -1
}

func TestBuildURIWithInvalidURL(t *testing.T) {
	instance := &config.CmonInstance{
		Url: "://invalid-url",
	}
	client := &Client{
		Instance: instance,
	}

	result := client.buildURI("info")
	// The URL actually gets processed as https://://invalid-url/v2/info since we prepend https://
	// This is not a perfect URL but it doesn't crash the parser, which is the main goal
	assert.Contains(t, result, "://invalid-url/v2/info")
}
