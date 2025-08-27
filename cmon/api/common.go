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
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	ModuleAuth        = "auth"
	ModuleAlarm       = "alarm"
	ModuleConfig      = "config"
	ModuleProc        = "proc"
	ModuleRepos       = "repos"
	ModuleDiscovery   = "discovery"
	ModuleCloud       = "cloud"
	ModuleReports     = "reports"
	ModuleUsers       = "users"
	ModuleMetatype    = "metatype"
	ModuleImperative  = "imperative"
	ModuleController  = "controller"
	ModuleAudit       = "audit"
	ModuleTree        = "tree"
	ModuleMaintenance = "maintenance"
	ModuleClusters    = "clusters"
	ModuleBackup      = "backup"
	ModuleJobs        = "jobs"
	ModuleLog         = "log"
	ModuleStat        = "stat"
	ModuleInfo        = "info"
	ModulePoolControllers = "poolcontrollers"


	RequestStatusOk              = "Ok"              // The request was successfully processed.
	RequestStatusInvalidRequest  = "InvalidRequest"  // Something was fundamentally wrong with the request.
	RequestStatusObjectNotFound  = "ObjectNotFound"  // The referenced object (e.g. the cluster) was not found.
	RequestStatusTryAgain        = "TryAgain"        // The request can not at the moment processed.
	RequestStatusClusterNotFound = "ClusterNotFound" // The cluster not found.
	RequestStatusUnknownError    = "UnknownError"    // The exact error could not be identified.
	RequestStatusAccessDenied    = "AccessDenied"    // The authenticated user has insufficient rights.
	RequestStatusAuthRequired    = "AuthRequired"    // The client has to Authenticate first.
	RequestStatusRedirect        = "Redirect"        // In case of cmon HA, the followers returns this.
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
	dbHostClassNames["CmonElasticHost"] = true
	dbHostClassNames["CmonRedisHost"] = true
	dbHostClassNames["CmonRedisSentinelHost"] = true
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
	case RequestStatusObjectNotFound, RequestStatusClusterNotFound:
		return http.StatusNotFound
	case RequestStatusTryAgain:
		return http.StatusTooEarly // FIXME, just playing here
	case RequestStatusUnknownError:
		return http.StatusInternalServerError
	case RequestStatusRedirect:
		return http.StatusTemporaryRedirect
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
	return fmt.Sprintf("%s: %s", err.Type, err.Message)
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
	Xid          string `json:"xid"`
	ControllerID string `json:"controller_id"`
}

type WithPoolId struct {
	PoolId string `json:"pool_id"`
}

type WithMultiXIds struct {
	Xids []string `json:"xids"`
}

func (wci *WithControllerID) HasID() bool {
	return len(wci.ControllerID) > 0 || len(wci.Xid) > 4
}

func (wci *WithControllerID) GetID() string {
	if len(wci.Xid) > 4 {
		return wci.Xid
	}
	return wci.ControllerID
}
