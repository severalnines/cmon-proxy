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

func (f *Filter) AcceptsValue(value string) bool {
	if len(value) < 1 {
		return true
	}
	for _, val := range f.Values {
		if val == value {
			return true
		}
	}
	return f.Value == value
}

func PassFilter(filters []*Filter, key, value string) bool {
	// no filters at all... fine
	if len(filters) < 1 {
		return true
	}

	for _, filter := range filters {
		if filter.Key == key {
			return filter.AcceptsValue(value)
		}
	}

	// the field isn't filtrated
	return true
}
