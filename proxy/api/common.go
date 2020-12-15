package api

// WithControllerID is used in replies to extend the standard cmon replies
type WithControllerID struct {
	ControllerID  string `json:"controller_id"`
	ControllerURL string `json:"controller_url"`
}

// Filter is a generic filter by a key and accepted values
type Filter struct {
	Key    string   `json:"key"`
	Value  string   `json:"value,omitempty"`
	Values []string `json:"values,omitempty"`
}
