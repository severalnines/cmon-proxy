package api

import (
	"strings"
)

type GetAlarmsRequest struct {
	*WithOperation `json:",inline"`
	*WithClusterID `json:",inline"`
}

type GetAlarmsReply struct {
	*WithControllerID `json:",inline"`
	*WithResponseData `json:",inline"`

	Alarms []*Alarm `json:"alarms"`
}

// Alarm struct.
type Alarm struct {
	AlarmId        int64    `json:"alarm_id"`
	ClusterId      uint64   `json:"cluster_id"`
	ComponentName  string   `json:"component_name"`
	Created        NullTime `json:"created"`
	Hostname       string   `json:"hostname"`
	Title          string   `json:"title"`
	Message        string   `json:"message"`
	Recommendation string   `json:"recommendation"`
	SeverityName   string   `json:"severity_name"`
	TypeName       string   `json:"type_name"`
}

// GetSeverity returns alarm severity.
func (a *Alarm) GetSeverity() string {
	return strings.Replace(a.SeverityName, "ALARM_", "", -1)
}

func (a *Alarm) Copy() *Alarm {
	return &Alarm{
		AlarmId:        a.AlarmId,
		ClusterId:      a.ClusterId,
		ComponentName:  a.ComponentName,
		Created:        a.Created,
		Hostname:       a.Hostname,
		Title:          a.Title,
		Message:        a.Message,
		Recommendation: a.Recommendation,
		SeverityName:   a.SeverityName,
		TypeName:       a.TypeName,
	}
}
