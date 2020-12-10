package cmon

import (
	"encoding/json"
	"fmt"

	"github.com/severalnines/cmon-proxy/cmon/api"
)

func (client *Client) ListBackups(req *api.ListBackupsRequest) (*api.ListBackupsResponse, error) {
	req.Operation = "getBackups"
	if req.WithClusterID == nil || req.WithClusterID.ClusterID < 1 {
		return nil, fmt.Errorf("invalid cluster id")
	}
	res := &api.ListBackupsResponse{}
	if err := client.Request(api.ModuleBackup, req, res); err != nil {
		return nil, err
	}
	if res.RequestStatus != api.RequestStatusOk {
		return nil, api.NewErrorFromResponseData(res.WithResponseData)
	}
	return res, nil
}

func (client *Client) ListBackupSchedules(req *api.ListBackupSchedulesRequest) (*api.ListBackupSchedulesResponse, error) {
	jobs, err := client.GetJobInstances(&api.GetJobInstancesRequest{
		WithClusterID: req.WithClusterID,
		WithLimit:     req.WithLimit,
		ShowScheduled: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to res backup schedules from cmon: %s", err.Error())
	}
	res := &api.ListBackupSchedulesResponse{
		WithResponseData: jobs.WithResponseData,
		WithTotal:        jobs.WithTotal,
		BackupSchedules:  make([]*api.BackupSchedule, 0, jobs.Total),
	}
	if jobs.Total == 0 {
		return res, nil
	}
	for _, j := range jobs.Jobs {
		if j.JobSpec == nil {
			continue
		}
		if j.JobSpec.Command != "backup" {
			continue
		}
		jd, err := j.JobSpec.GetBackupJobData()
		if err != nil {
			return nil, fmt.Errorf(
				"failed to parse job_spec of job %d to BackupJobData: %s", j.JobID, err.Error())
		}
		res.BackupSchedules = append(res.BackupSchedules, &api.BackupSchedule{
			ClusterID:  j.ClusterID,
			Enabled:    true,
			Recurrence: j.Recurrence,
			Job:        jd,
			ID:         j.JobID,
			Created:    j.Created,
			Status:     j.Status,
		})

	}
	return res, nil
}

func (client *Client) RestoreBackup(req *api.RestoreBackupRequest) (*api.RestoreBackupResponse, error) {
	jd, err := json.Marshal(&api.RestoreBackupJobData{
		BackupDatadirBeforeRestore: false,
		BackupID:                   req.BackupID,
		Bootstrap:                  true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal backup job data: %s", err.Error())
	}
	jRes, err := client.CreateJobInstance(&api.CreateJobInstanceRequest{
		WithClusterID: req.WithClusterID,
		Job: &api.Job{
			WithClassName: &api.WithClassName{
				ClassName: "CmonJobInstance",
			},
			JobSpec: &api.JobSpec{
				Command: "restore_backup",
				JobData: jd,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create restore backup job: %s", err.Error())
	}
	return &api.RestoreBackupResponse{WithControllerID: jRes.WithControllerID, Job: jRes.Job}, nil
}
