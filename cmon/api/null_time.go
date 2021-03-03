package api

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
