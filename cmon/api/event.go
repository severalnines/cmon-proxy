package api

type Event struct {
	*WithControllerID `json:",inline"`
	*WithClassName    `json:",inline"`

	EventClass     string          `json:"event_class"`
	EventName      string          `json:"event_name"`
	EventOrigins   *EventOrigins   `json:"event_origins"`
	EventSpecifics *EventSpecifics `json:"event_specifics"`
}

func (event *Event) IsJob() bool {
	return event.EventClass == "EventJob"
}

func (event *Event) IsJobFailed() bool {
	j := event.GetJob()
	return j != nil && j.Status == JobStatusFailed
}

func (event *Event) IsAlarm() bool {
	return event.EventClass == "EventAlarm"
}

func (event *Event) GetJob() *Job {
	if event.EventSpecifics != nil {
		return event.EventSpecifics.Job
	}
	return nil
}

func (event *Event) GetAlarm() *Alarm {
	if event.EventSpecifics != nil {
		return event.EventSpecifics.Alarm
	}
	return nil
}

func (event *Event) GetClusterID() int64 {
	if event.EventSpecifics != nil {
		return event.EventSpecifics.ClusterId
	}
	return 0
}

func (event *Event) IsCreated() bool {
	return event.EventName == "CreatedAt"
}

func (event *Event) IsChanged() bool {
	return event.EventName == "Changed"
}

func (event *Event) IsEnded() bool {
	return event.EventName == "Ended"
}

type EventOrigins struct {
	Created    int64  `json:"tv_sec,omitempty"`
	CreatedN   int64  `json:"tv_nsec,omitempty"`
	SenderFile string `json:"sender_file,omitempty"`
	SenderLine int64  `json:"sender_line,omitempty"`
}

type EventSpecifics struct {
	ClusterId int64  `json:"cluster_id"`
	Alarm     *Alarm `json:"alarm,omitempty"`
	Job       *Job   `json:"job,omitempty"`
}
