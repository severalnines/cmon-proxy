package api

import "strings"

// WithControllerID is used in replies to extend the standard cmon replies
type WithControllerID struct {
	ControllerID  string `json:"controller_id"`
	ControllerURL string `json:"controller_url"`
}

type ListRequest struct {
	Page    uint64    `json:"page"`
	PerPage uint64    `json:"perPage"`
	Order   string    `json:"order"`
	Filters []*Filter `json:"filters"`
}

type ListResponse struct {
	Page    uint64 `json:"page,omitempty"`
	PerPage uint64 `json:"perPage,omitempty"`
	Total   uint64 `json:"total,omitempty"`
}

// Filter is a generic filter by a key and accepted values
type Filter struct {
	Key    string   `json:"key"`
	Value  string   `json:"value,omitempty"`
	Values []string `json:"values,omitempty"`
}

func (f *Filter) AcceptsValue(value string) bool {
	if f == nil || len(value) < 1 {
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
	if filters == nil || len(filters) < 1 {
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

type LazyStringFn func() string

func PassFilterLazy(filters []*Filter, key string, fn LazyStringFn) bool {
	// no filters at all... fine
	if filters == nil || len(filters) < 1 {
		return true
	}

	for _, filter := range filters {
		if filter.Key == key {
			return filter.AcceptsValue(fn())
		}
	}

	// the field isn't filtrated
	return true
}

func (listRequest ListRequest) GetOrder() (order string, descending bool) {
	order = ""
	descending = false
	parts := strings.Split(listRequest.Order, " ")
	if len(parts) >= 2 {
		descending = strings.ToLower(parts[1]) == "desc"
	}
	if len(parts) > 0 {
		order = parts[0]
	}
	return
}

func Paginate(listRequest ListRequest, length int) (int, int) {
	if listRequest.PerPage <= 0 {
		return 0, length
	}

	// UI starts counting from 1, but we need it from 0 here
	page := listRequest.Page - 1
	// hack but we don't want invalid data here, it would crash
	if page < 0 {
		page = 0
	}

	start := int(page * listRequest.PerPage)
	if start > length {
		start = length
	}

	end := start + int(listRequest.PerPage)
	if end > length {
		end = length
	}

	return start, end
}
