package cmon

import (
	"fmt"
	"strings"
	"time"

	"github.com/severalnines/cmon-proxy/cmon/api"
	"github.com/severalnines/cmon-proxy/retry"
)

func (client *Client) GetBackupJobs(clusterIds []uint64) ([]*api.Job, error) {
	// NOTE: we assume the clusters wont have too many scheduled jobs
	req := &api.GetJobInstancesManyRequest{
		WithOperation:  &api.WithOperation{Operation: "getJobInstances"},
		WithClusterIDs: &api.WithClusterIDs{ClusterIDs: clusterIds},
		ShowScheduled:  true, /* ask only scheduled jobs */
	}
	res := &api.GetJobInstancesResponse{}
	if err := client.Request(api.ModuleJobs, req, res); err != nil {
		return nil, err
	}
	if res.RequestStatus != api.RequestStatusOk {
		return nil, api.NewErrorFromResponseData(res.WithResponseData)
	}
	retval := make([]*api.Job, 0, len(res.Jobs))
	for idx, job := range res.Jobs {
		// and skip any scheduled non-backup jobs
		if strings.ToLower(job.Command()) != "backup" {
			continue
		}

		retval = append(retval, res.Jobs[idx])
	}
	return retval, nil
}

func (client *Client) GetJobInstances(req *api.GetJobInstancesRequest) (*api.GetJobInstancesResponse, error) {
	req.WithOperation = &api.WithOperation{Operation: "getJobInstances"}
	if err := api.CheckClusterID(req); err != nil {
		return nil, err
	}
	res := &api.GetJobInstancesResponse{}
	if err := client.Request(api.ModuleJobs, req, res); err != nil {
		return nil, err
	}
	if res.RequestStatus != api.RequestStatusOk {
		return nil, api.NewErrorFromResponseData(res.WithResponseData)
	}
	return res, nil
}

//GetLastJobs returns the jobs for the specified clusters from the last N hours, and we may have some data already from the past
func (client *Client) GetLastJobs(clusterIds []uint64, lastNhours int, haveBefore ...time.Time) ([]*api.Job, error) {
	perPage := int64(32)
	req := &api.GetJobInstancesManyRequest{
		WithOperation:  &api.WithOperation{Operation: "getJobInstances"},
		WithClusterIDs: &api.WithClusterIDs{ClusterIDs: clusterIds},
		ShowScheduled:  false,
		WithLimit: &api.WithLimit{
			Limit: perPage,
		},
	}
	req.Operation = "getJobInstances"

	count := 0
	retval := make([]*api.Job, 0, len(clusterIds)*10)
	timestamp := time.Now().Add(time.Hour * time.Duration(-lastNhours))

	for {
		// this returns the jobs descending (by jobid)
		res := &api.GetJobInstancesResponse{}
		if err := client.Request(api.ModuleJobs, req, res); err != nil {
			return nil, err
		}
		if res.RequestStatus != api.RequestStatusOk {
			return nil, api.NewErrorFromResponseData(res.WithResponseData)
		}

		// gonna break when there are no more entries
		endReached := len(res.Jobs) == 0

		for _, job := range res.Jobs {
			// to avoid duplicates, skip already seen jobs
			if count > 0 && retval[count-1].JobID <= job.JobID {
				continue
			}

			// okay, this job is too old, stop now
			if job.Created.T.Before(timestamp) {
				endReached = true
				break
			}

			retval = append(retval, job)
			count++
		}

		if endReached {
			break
		}

		req.Offset += perPage
	}

	return retval, nil
}

func (client *Client) GetJobInstance(req *api.GetJobInstanceRequest) (*api.GetJobInstanceResponse, error) {
	req.Operation = "getJobInstance"
	//if err := checkClusterID(req); err != nil {
	//	return nil, err
	//}
	res := &api.GetJobInstanceResponse{}
	if err := client.Request(api.ModuleJobs, req, res); err != nil {
		return nil, err
	}
	if res.RequestStatus != api.RequestStatusOk {
		return nil, api.NewErrorFromResponseData(res.WithResponseData)
	}
	return res, nil
}

func (client *Client) CreateJobInstance(req *api.CreateJobInstanceRequest) (*api.CreateJobInstanceResponse, error) {
	req.Operation = "createJobInstance"
	if req.Job != nil {
		if req.Job.WithClassName == nil {
			req.Job.WithClassName = &api.WithClassName{ClassName: "CmonJobInstance"}
		} else {
			req.Job.WithClassName.ClassName = "CmonJobInstance"
		}
	}
	res := &api.CreateJobInstanceResponse{}
	if err := client.Request(api.ModuleJobs, req, res); err != nil {
		return nil, err
	}
	if res.RequestStatus != api.RequestStatusOk {
		return nil, api.NewErrorFromResponseData(res.WithResponseData)
	}
	return res, nil
}

func (client *Client) CreateJobInstanceWait(
	req *api.CreateJobInstanceRequest,
	retryConfig *retry.Config,
	progress api.JobProgressFunc) (*api.CreateJobInstanceResponse, error) {
	cjr, err := client.CreateJobInstance(req)
	if err != nil {
		return nil, err
	}
	gjir := &api.GetJobInstanceRequest{
		JobID: cjr.Job.JobID,
	}
	errJobFailed := fmt.Errorf("job failed")
	errJobRunning := fmt.Errorf("job in progress")
	var gjr *api.GetJobInstanceResponse
	if err := retry.Do(
		func(_ int) error {
			var err error
			gjr, err = client.GetJobInstance(gjir)
			if err != nil {
				return fmt.Errorf("failed to fetch job: %s", err.Error())
			}
			if progress != nil {
				// send job progress if progress is defined
				progress(
					gjr.Job.HasProgress,
					gjr.Job.ProgressPercent,
					gjr.Job.StatusText)
			}
			switch gjr.Job.Status {
			case api.JobStatusFinished:
				return nil
			case api.JobStatusFailed:
				return errJobFailed
			case api.JobStatusAborted:
				return errJobFailed
			}
			return errJobRunning
		},
		func(err error, _ int) error {
			if err == errJobFailed {
				return fmt.Errorf(gjr.Job.StatusText)
			}
			return nil
		}, retryConfig); err != nil {
		return nil, fmt.Errorf(
			"waited for job %d to finish for %d and gave up: %s",
			gjir.JobID, retryConfig.Seconds(), err.Error())
	}
	return &api.CreateJobInstanceResponse{
		WithResponseData: gjr.WithResponseData,
		Job:              gjr.Job,
	}, nil
}
