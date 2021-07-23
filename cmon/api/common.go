package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	ModuleAuth     = "auth"
	ModuleAlarm    = "alarm"
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

var (
	// qt is used in SQLProcess.GetQueryTime(), defined in init()
	qt time.Time

	dbHostClassNames map[string]bool
)

func init() {
	qt, _ = time.Parse("15:04:05", "00:00:00")

	dbHostClassNames = make(map[string]bool)
	dbHostClassNames["CmonMySqlHost"] = true
	dbHostClassNames["CmonGaleraHost"] = true
	dbHostClassNames["CmonGroupReplHost"] = true
	dbHostClassNames["CmonMongoHost"] = true
	dbHostClassNames["CmonNdbHost"] = true
	dbHostClassNames["CmonPostgreSqlHost"] = true
	dbHostClassNames["CmonRedisHost"] = true
}

func NewError(t, m string) error {
	return &Error{t, m}
}

func NewErrorFromResponseData(d *WithResponseData) error {
	return &Error{d.RequestStatus, d.ErrorString}
}

// CtxWriteError writes an error object to the JSON, in case of regural (non Error) errors you may specify a custom httpStatus in the optional argument
func CtxWriteError(ctx *gin.Context, err error, httpStatus ...int) {
	if err == nil {
		err = NewError(RequestStatusOk, "OK")
	}

	switch e := err.(type) {
	case *Error:
		ctx.JSON(RequestStatusToStatusCode(e.Type), e)
	default:
		statusCode := http.StatusInternalServerError
		if len(httpStatus) > 0 && httpStatus[0] > 0 {
			statusCode = httpStatus[0]
		}
		ctx.JSON(statusCode, NewError(RequestStatusUnknownError, err.Error()))
	}
}

func RequestStatusToStatusCode(requestStatus string) int {
	switch requestStatus {
	case RequestStatusInvalidRequest:
		return http.StatusBadRequest
	case RequestStatusObjectNotFound:
		return http.StatusNotFound
	case RequestStatusTryAgain:
		return http.StatusTooEarly // FIXME, just playing here
	case RequestStatusUnknownError:
		return http.StatusInternalServerError
	case RequestStatusAccessDenied, RequestStatusAuthRequired:
		return http.StatusUnauthorized
	case RequestStatusOk:
		fallthrough
	default:
		return http.StatusOK
	}
}

func ErrorToStatusCode(err error) int {
	if err == nil {
		return http.StatusOK
	}
	switch t := err.(type) {
	case *Error:
		return RequestStatusToStatusCode(t.Type)
	default:
		return http.StatusInternalServerError
	}
}

type Error struct {
	Type    string `json:"type,omitempty"`
	Message string `json:"message,omitempty"`
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

type WithClusterIDs struct {
	ClusterIDs []uint64 `json:"cluster_ids,omitempty"`
}

type WithClusterIDForced struct {
	ClusterID uint64 `json:"cluster_id,"`
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
	RequestID        uint64   `json:"request_id,omitempty"`
	RequestCreated   NullTime `json:"request_created,omitempty"`
	RequestProcessed NullTime `json:"request_processed,omitempty"`
	RequestStatus    string   `json:"request_status,omitempty"`
	ErrorString      string   `json:"error_string,omitempty"`
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
	Tags []string `json:"tags,omitempty"`
}

type WithGroup struct {
	GroupID   uint64 `json:"group_id"`
	GroupName string `json:"group_name"`
}

type WithControllerID struct {
	ControllerID string `json:"controller_id"`
}
