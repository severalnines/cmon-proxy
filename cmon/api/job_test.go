package api

import (
	"encoding/json"
	"testing"
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
