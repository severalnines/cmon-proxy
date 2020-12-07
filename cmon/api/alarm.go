package api

import (
	"strings"
)

// Alarm struct.
type Alarm struct {
	AlarmId        int64  `json:"alarm_id"`
	ComponentName  string `json:"component_name"`
	Hostname       string `json:"hostname"`
	Title          string `json:"title"`
	Message        string `json:"message"`
	Recommendation string `json:"recommendation"`
	Severity       string `json:"severity_name"`
}

// GetSeverity returns alarm severity.
func (a *Alarm) GetSeverity() string {
	return strings.Replace(a.Severity, "ALARM_", "", -1)
}
