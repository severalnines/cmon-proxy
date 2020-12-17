package api

type AlarmsOverview struct {
	// Alarm counts by severity
	AlarmCounts map[string]int `json:"alarm_counts"`
	// Alarm counts by type
	AlarmTypes map[string]int `json:"alarm_types"`

	// Alarm counts by controller
	AlarmCountsByController map[string]*AlarmsOverview `json:"by_controller,omitempty"`
}
