package api

// Copyright 2022 Severalnines AB
//
// This file is part of cmon-proxy.
//
// cmon-proxy is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 2 of the License.
//
// cmon-proxy is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with cmon-proxy. If not, see <https://www.gnu.org/licenses/>.

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestJobSpec_UnmarshalJSON(t *testing.T) {
	type S struct {
		JobSpec *JobSpec `json:"jobspec,omitempty"`
	}
	// the cmon seems to send both objects and strings
	j1 := []byte(`{"jobspec":{"command":"backup","job_data":{"hostname": "backupHostA"}}}`)
	j2 := []byte(`{"jobspec":"{\n    \"command\": \"restart\",\n    \"group_id\": 1,\n    \"group_name\": \"admins\",\n    \"user_id\": 1,\n    \"user_name\": \"kedazo@severalnines.com\",\n    \"job_data\": \n    {\n        \"clusterId\": \"11\",\n        \"force_stop\": true,\n        \"hostname\": \"10.216.188.234\",\n        \"port\": 5432,\n        \"stop_timeout\": 1800\n    }\n}"}`)
	j3 := []byte(`{"jobspec":"Galera Node Recovery"}`)
	s1 := new(S)
	if err := json.Unmarshal(j1, s1); err != nil {
		t.Error(err)
	}
	if s1.JobSpec.Command != "backup" {
		t.Errorf("expected 'backup' got '%s'", s1.JobSpec.Command)
	}
	s2 := new(S)
	if err := json.Unmarshal(j2, s2); err != nil {
		t.Error(err)
	}
	if s2.JobSpec.Command != "restart" {
		t.Errorf("expected 'restart' got '%s'", s2.JobSpec.Command)
	}
	s3 := new(S)
	if err := json.Unmarshal(j3, s3); err != nil {
		t.Error(err)
	}
	if s3.JobSpec.Command != "Galera Node Recovery" {
		t.Errorf("expected 'Galera Node Recovery' got '%s'", s3.JobSpec.Command)
	}
}

func TestJob_ProgressPercentInt_Unmarshal(t *testing.T) {
	a := assert.New(t)

	t.Run("empty", func(t *testing.T) {
		j := Job{}

		err := json.Unmarshal([]byte(`{}`), &j)

		a.Nil(err)
	})

	t.Run("int number", func(t *testing.T) {
		j := Job{}

		err := json.Unmarshal([]byte(`{"progress_percent": 123}`), &j)

		a.Nil(err)
		a.Equal(123, j.ProgressPercentInt())
	})

	t.Run("int string", func(t *testing.T) {
		j := Job{}

		err := json.Unmarshal([]byte(`{"progress_percent": "124"}`), &j)

		a.Nil(err)
		a.Equal(124, j.ProgressPercentInt())
	})

	t.Run("float number", func(t *testing.T) {
		j := Job{}

		err := json.Unmarshal([]byte(`{"progress_percent": 125.6}`), &j)

		a.Nil(err)
		a.Equal(125, j.ProgressPercentInt())
	})

	t.Run("float string", func(t *testing.T) {
		j := Job{}

		err := json.Unmarshal([]byte(`{"progress_percent": "126.7"}`), &j)

		a.Nil(err)
		a.Equal(126, j.ProgressPercentInt())
	})

	t.Run("null", func(t *testing.T) {
		j := Job{}

		err := json.Unmarshal([]byte(`{"progress_percent": null}`), &j)

		a.Nil(err)
		a.Equal(0, j.ProgressPercentInt())
	})

	t.Run("zero string", func(t *testing.T) {
		j := Job{}

		err := json.Unmarshal([]byte(`{"progress_percent": "0"}`), &j)

		a.Nil(err)
		a.Equal(0, j.ProgressPercentInt())
	})
}
