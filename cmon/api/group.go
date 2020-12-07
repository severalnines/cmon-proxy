package api

type Group struct {
	WithClassName `json:",inline"`

	GroupID   uint64 `json:"group_id"`
	GroupName string `json:"group_name"`
}
