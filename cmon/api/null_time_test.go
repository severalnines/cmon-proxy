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
	"time"
)

func TestNullTime_UnmarshalJSON(t *testing.T) {
	type S struct {
		Date NullTime `json:"date"`
	}
	j1 := []byte(`{"date":"null"}`)
	j2 := []byte(`{"date":null}`)
	j3 := []byte(`{"date":"2020-01-01T12:00:01.000Z"}`)
	s1 := new(S)
	if err := json.Unmarshal(j1, s1); err != nil {
		t.Error(err)
	}
	if s1.Date.String() != "" {
		t.Errorf("expected %s, got %s", "", s1.Date.String())
	}
	s2 := new(S)
	if err := json.Unmarshal(j2, s2); err != nil {
		t.Error(err)
	}
	if s2.Date.String() != "" {
		t.Errorf("expected %s, got %s", "", s2.Date.String())
	}
	s3 := new(S)
	if err := json.Unmarshal(j3, s3); err != nil {
		t.Error(err)
	}
	if s3.Date.String() != "2020-01-01T12:00:01Z" {
		t.Errorf("expected %s, got %s", "2020-01-01T12:00:01Z", s3.Date.String())
	}
}

func TestNullTime_MarshalJSON(t *testing.T) {
	type S struct {
		Date NullTime `json:"date"`
	}
	n := time.Now()
	s1 := &S{NullTime{n}}
	b1, err := json.Marshal(s1)
	if err != nil {
		t.Error(err)
	}
	if string(b1) != `{"date":"`+n.Format(time.RFC3339)+`"}` {
		t.Errorf("expected %s, got %s", `{"date":"`+n.Format(time.RFC3339)+`"}`, string(b1))
	}
}
