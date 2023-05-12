package cmon

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
	"encoding/json"
	"fmt"
	"time"

	"github.com/severalnines/cmon-proxy/cmon/api"
)

func (client *Client) ListBackups(req *api.ListBackupsRequest) (*api.ListBackupsResponse, error) {
	req.Operation = "getBackups"
	if req.WithClusterID == nil || req.WithClusterID.ClusterID < 1 {
		return nil, fmt.Errorf("invalid cluster id")
	}
	req.BackupRecordVersion = 2
	res := &api.ListBackupsResponse{}
	if err := client.Request(api.ModuleBackup, req, res); err != nil {
		return nil, err
	}
	if res.RequestStatus != api.RequestStatusOk {
		return nil, api.NewErrorFromResponseData(res.WithResponseData)
	}
	return res, nil
}

// GetLastBackups returns the backups for the specified clusters from the last N days
func (client *Client) GetLastBackups(clusterIds []uint64, lastNdays int, haveBefore ...time.Time) ([]*api.Backup, error) {
	perPage := int64(32)
	req := &api.ListBackupsRequest{
		WithOperation: &api.WithOperation{Operation: "getBackups"},
		WithClusterID: &api.WithClusterID{},
		WithLimit: &api.WithLimit{
			Limit: perPage,
		},
	}

	retval := make([]*api.Backup, 0, len(clusterIds)*10)
	timestamp := time.Now().Add(time.Hour * time.Duration(-lastNdays*24))

	if len(clusterIds) < 1 {
		// means request from all clusters
		clusterIds = []uint64{0}
	}

	req.BackupRecordVersion = 2
	for _, req.ClusterID = range clusterIds {
		// start from page 0
		req.Offset = 0
		for {
			// this returns the backups descending (by backup id)
			res := &api.ListBackupsResponse{}
			if err := client.Request(api.ModuleBackup, req, res); err != nil {
				return nil, err
			}
			if res.RequestStatus != api.RequestStatusOk {
				if res.RequestStatus == api.RequestStatusClusterNotFound ||
					res.RequestStatus == api.RequestStatusObjectNotFound ||
					res.RequestStatus == api.RequestStatusAccessDenied {
					// cluster getting deleted or our access got revoked
					// must not block the whole request -> just skip this cluster
					break
				}
				return nil, api.NewErrorFromResponseData(res.WithResponseData)
			}

			// gonna break when there are no more entries
			endReached := len(res.Backups) == 0

			for _, backup := range res.Backups {
				count := len(retval)
				// to avoid duplicates, skip already seen backups
				if count > 0 && retval[count-1].Metadata.ID <= backup.Metadata.ID {
					continue
				}

				// okay, this job is too old, stop now
				if backup.Metadata.Created.T.Before(timestamp) {
					endReached = true
					break
				}

				retval = append(retval, backup)
			}

			if endReached {
				break
				// continue with next cluster
			}

			req.Offset += perPage
			// paginate till we reach the oldest backup
		}
	}

	return retval, nil
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
