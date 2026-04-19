package config

// Copyright 2026 Severalnines AB
//
// This file is part of cmon-proxy.
//
// cmon-proxy is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 2 of the License.
//
// cmon-proxy is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with cmon-proxy. If not, see <https://www.gnu.org/licenses/>.

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfigHasCcTelemetryFields(t *testing.T) {
	cfg := Config{}
	// Struct must declare these fields so they yaml-decode cleanly.
	cfg.CcTelemetryURL = "http://localhost:9520"
	cfg.CcTelemetryToken = "secret"
	assert.Equal(t, "http://localhost:9520", cfg.CcTelemetryURL)
	assert.Equal(t, "secret", cfg.CcTelemetryToken)
}
