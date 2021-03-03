package api

type CmonStatus string

var (
	CmonStatuses = []CmonStatus{
		Ok,
		Failed,
		AuthenticationError,
	}
)

// String implements Stringer interface
func (st CmonStatus) String() string {
	return string(st)
}

const (
	Ok                  CmonStatus = "ok"
	Failed              CmonStatus = "failed"
	AuthenticationError CmonStatus = "authentication-error"
)

type ControllerStatus struct {
	ControllerID  string     `json:"controller_id"`
	Name          string     `json:"controller_name"`
	Url           string     `json:"url"`
	FrontendUrl   string     `json:"fronted_url,omitempty"`
	Version       string     `json:"version"`
	StatusMessage string     `json:"status_message"`
	Status        CmonStatus `json:"status"`
}

type ControllerStatusList struct {
	Controllers []*ControllerStatus `json:"controllers"`
}
