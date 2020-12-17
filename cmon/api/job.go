package api

import (
	"encoding/json"
	"fmt"
	"time"
)

type GetJobInstancesRequest struct {
	*WithOperation `json:",inline"`
	*WithClusterID `json:",inline"`
	*WithLimit     `json:",inline"`

	ShowScheduled bool     `json:"show_scheduled,omitempty"`
	Tags          []string `json:"tags,omitempty"`
}

type GetJobInstancesResponse struct {
	*WithControllerID `json:",inline"`
	*WithResponseData `json:",inline"`
	*WithTotal        `json:",inline"`

	Jobs []*Job `json:"jobs"`
}

type GetJobInstanceRequest struct {
	*WithOperation `json:",inline"`
	*WithClusterID `json:",inline"`

	JobID uint64 `json:"job_id"`
}

type GetJobInstanceResponse struct {
	*WithControllerID `json:",inline"`
	*WithResponseData `json:",inline"`

	Job *Job `json:"job"`
}

type CreateJobInstanceRequest struct {
	*WithOperation `json:",inline"`
	*WithClusterID `json:",inline"`

	Job *Job `json:"job"`
}

type CreateJobInstanceResponse struct {
	*WithControllerID `json:",inline"`
	*WithResponseData `json:",inline"`

	Job *Job `json:"job"`
}

// CMON job statuses, taken from:
// https://severalnines.com/downloads/cmon/cmon-docs/current/jobclasses.html
const (
	JobStatusDefined    = "DEFINED"
	JobStatusDequeued   = "DEQUEUED"
	JobStatusRunning    = "RUNNING"
	JobStatusRunning2   = "RUNNING2"
	JobStatusRunning3   = "RUNNING3"
	JobStatusRunningExt = "RUNNING_EXT"
	JobStatusAborted    = "ABORTED"
	JobStatusFinished   = "FINISHED"
	JobStatusFailed     = "FAILED"
)

type Job struct {
	*WithClassName `json:",inline"`
	*WithOwner     `json:",inline"`
	*WithTags      `json:",inline"`
	*WithClusterID `json:",inline"`
	*WithUser      `json:",inline"`
	*WithGroup     `json:",inline"`

	CanBeAborted    bool      `json:"can_be_aborted,omitempty"`
	CanBeDeleted    bool      `json:"can_be_deleted,omitempty"`
	Created         time.Time `json:"created,omitempty"`
	Ended           time.Time `json:"ended,omitempty"`
	ExitCode        int64     `json:"exit_code,omitempty"`
	IPAddress       string    `json:"ip_address,omitempty"`
	JobID           uint64    `json:"job_id,omitempty"`
	ParentJobID     uint64    `json:"parent_job_id,omitempty"`
	RPCVersion      string    `json:"rpc_version,omitempty"`
	Started         time.Time `json:"started,omitempty"`
	Status          string    `json:"status,omitempty"`
	StatusText      string    `json:"status_text,omitempty"`
	Title           string    `json:"title,omitempty"`
	Recurrence      string    `json:"recurrence,omitempty"`
	JobSpec         *JobSpec  `json:"job_spec,omitempty"`
	HasProgress     bool      `json:"has_progress"`
	ProgressPercent int       `json:"progress_percent"`
	Tags            string    `json:"tags,omitempty"`
}

type JobSpec struct {
	Command string          `json:"command"`
	JobData json.RawMessage `json:"job_data"`
}

func (js *JobSpec) GetBackupJobData() (*BackupJobData, error) {
	bjd := &BackupJobData{}
	if err := json.Unmarshal(js.JobData, bjd); err != nil {
		return nil, fmt.Errorf("failed to parse backup job data: %s", err.Error())
	}
	return bjd, nil
}

type JobProgressFunc func(hasProgress bool, progress int, statusText string)

type BackupJobData struct {
	BackupFailover     bool   `json:"backup_failover"`
	BackupFailoverHost string `json:"backup_failover_host"`
	BackupMethod       string `json:"backup_method"`
	BackupRetention    int64  `json:"backup_retention"`
	BackupDir          string `json:"backupdir"`
	//CCStorage          string `json:"cc_storage"` //todo: think on howto fix this, cc_storage can be bool/int/string
	Compression      bool   `json:"compression"`
	CompressionLevel int64  `json:"compression_level"`
	Hostname         string `json:"hostname"`
	Port             int64  `json:"port"`
	RPCVersion       string `json:"rpc_version"`
	WSREPDesync      bool   `json:"wsrep_desync"`
}

type CreateClusterJobData struct {
	ClusterName     string                  `json:"cluster_name"`
	ClusterType     string                  `json:"cluster_type"`
	Nodes           []*CreateClusterJobNode `json:"nodes"`
	SshUser         string                  `json:"ssh_user"`
	SshKeyfile      string                  `json:"ssh_keyfile"`
	Vendor          string                  `json:"vendor"`
	Version         string                  `json:"version"`
	WithTags        string                  `json:"with_tags"`
	InstallSoftware bool                    `json:"install_software"`
	EnableUninstall bool                    `json:"enable_uninstall"`
}

type CreateClusterJobNode struct {
	Hostname string `json:"hostname"`
}
