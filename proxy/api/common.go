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
	"strings"
)

type SimpleFilteredRequest struct {
	Filters []*Filter `json:"filters"`
}

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
	Key      string   `json:"key"`
	Value    string   `json:"value,omitempty"`
	Values   []string `json:"values,omitempty"`   /* OR like filter */
	MatchAll []string `json:"matchall,omitempty"` /* all values specified here must match, for tags */
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

type LazyStringSlFn func() []string

// PassTagsFilterLazy checks if all the defined tags in filter.MatchAll are in the 'tags' list
func PassTagsFilterLazy(filters []*Filter, tagsFn LazyStringSlFn) bool {
	for _, filter := range filters {
		if filter == nil || filter.Key != "tags" || len(filter.MatchAll) < 1 {
			continue
		}

		tags := tagsFn()
		tagsMap := make(map[string]bool)
		for _, tag := range tags {
			tagsMap[tag] = true
		}

		for _, tag := range filter.MatchAll {
			if _, found := tagsMap[tag]; !found {
				// one of the required tags not found, fail
				return false
			}
		}

		// all tags found
		return true
	}

	// no tags filter present
	return true
}

func PassFilter(filters []*Filter, key, value string) bool {
	// no filters at all... fine
	if filters == nil || len(filters) < 1 {
		return true
	}

	for _, filter := range filters {
		if filter != nil && filter.Key == key {
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
		if filter != nil && filter.Key == key {
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
