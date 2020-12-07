package api

import (
	"fmt"
	"time"
)

const (
	ModuleAuth     = "auth"
	ModuleClusters = "clusters"
	ModuleBackup   = "backup"
	ModuleJobs     = "jobs"
	ModuleStat     = "stat"

	RequestStatusOk             = "Ok"             // The request was successfully processed.
	RequestStatusInvalidRequest = "InvalidRequest" // Something was fundamentally wrong with the request.
	RequestStatusObjectNotFound = "ObjectNotFound" // The referenced object (e.g. the cluster) was not found.
	RequestStatusTryAgain       = "TryAgain"       // The request can not at the moment processed.
	RequestStatusUnknownError   = "UnknownError"   // The exact error could not be identified.
	RequestStatusAccessDenied   = "AccessDenied"   // The authenticated user has insufficient rights.
	RequestStatusAuthRequired   = "AuthRequired"   // The client has to Authenticate first.
)

func NewError(t, m string) error {
	return &Error{t, m}
}

func NewErrorFromResponseData(d *WithResponseData) error {
	return &Error{d.RequestStatus, d.ErrorString}
}

type Error struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

func (err Error) Error() string {
	return fmt.Sprintf("%s: %s",
		err.Type,
		err.Message)
}

type WithOperation struct {
	Operation string `json:"operation"`
}

type HasClusterID interface {
	GetClusterID() uint64
}

type WithClusterID struct {
	ClusterID uint64 `json:"cluster_id,omitempty"`
}

func (wci *WithClusterID) GetClusterID() uint64 {
	if wci == nil {
		return 0
	}
	return wci.ClusterID
}

func CheckClusterID(cid HasClusterID) error {
	if cid.GetClusterID() < 1 {
		return fmt.Errorf("invalid/empty cluster id")
	}
	return nil
}

type WithClassName struct {
	ClassName string `json:"class_name"`
}

type WithResponseData struct {
	RequestID        uint64    `json:"request_id"`
	RequestCreated   time.Time `json:"request_created"`
	RequestProcessed time.Time `json:"request_processed"`
	RequestStatus    string    `json:"request_status"`
	ErrorString      string    `json:"error_string"`
}

type WithTotal struct {
	Total int64 `json:"total"`
}

type WithLimit struct {
	Limit  int64 `json:"limit"`
	Offset int64 `json:"offset"`
}

type WithUser struct {
	UserID   uint64 `json:"user_id"`
	UserName string `json:"user_name"`
}

type WithOwner struct {
	OwnerUserID   uint64 `json:"owner_user_id"`
	OwnerUserName string `json:"owner_user_name"`
}

type WithTags struct {
	Tags []string `json:"tags"`
}

type WithGroup struct {
	GroupID   uint64 `json:"group_id"`
	GroupName string `json:"group_name"`
}
