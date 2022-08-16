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
	"fmt"
	"time"
)

// NullTime is a hack to allow parsing time from cmon that might
// be returned as "null" or null or "2020-01-01T12:00:00.000Z".
type NullTime struct {
	T time.Time
}

// String returns datetime string in RFC3339.
func (nt *NullTime) String() string {
	if nt == nil || nt.T.IsZero() {
		return ""
	}
	return nt.T.Format(time.RFC3339)
}

// UnmarshalJSON implements json.Unmarshaler.
func (nt *NullTime) UnmarshalJSON(b []byte) error {
	if b == nil || string(b) == "" {
		nt.T = time.Time{}
		return nil
	}
	if string(b) == `"null"` || string(b) == "null" {
		nt.T = time.Time{}
		return nil
	}
	if err := json.Unmarshal(b, &nt.T); err != nil {
		return fmt.Errorf("failed to parse date: %s", err.Error())
	}
	return nil
}

// MarshalJSON implements json.Marshaler.
func (nt *NullTime) MarshalJSON() ([]byte, error) {
	return json.Marshal(nt.String())
}
