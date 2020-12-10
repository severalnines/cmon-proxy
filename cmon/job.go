package cmon

import (
	"fmt"

	"github.com/severalnines/ccx/go/retry"
	"github.com/severalnines/cmon-proxy/cmon/api"
)

func (client *Client) GetJobInstances(req *api.GetJobInstancesRequest) (*api.GetJobInstancesResponse, error) {
	req.Operation = "getJobInstances"
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
