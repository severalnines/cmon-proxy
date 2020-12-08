package api

import (
	"time"
)

type ListBackupsRequest struct {
	*WithOperation `json:",inline"`
	*WithClusterID `json:",inline"`
	*WithLimit     `json:",inline"`

	Ascending bool  `json:"ascending"`
	ParentID  int64 `json:"parent_id"`
}

type ListBackupsResponse struct {
	*WithControllerID `json:",inline"`
	*WithResponseData `json:",inline"`
	*WithTotal        `json:",inline"`

	Backups []*Backup `json:"backup_records"`
}

type ListBackupSchedulesRequest struct {
	*WithOperation `json:",inline"`
	*WithClusterID `json:",inline"`
	*WithLimit     `json:",inline"`
}

type ListBackupSchedulesResponse struct {
	*WithControllerID `json:",inline"`
	*WithResponseData `json:",inline"`
	*WithTotal        `json:",inline"`

	BackupSchedules []*BackupSchedule `json:"backup_schedules"`
}

type RestoreBackupRequest struct {
	*WithClusterID `json:",inline"`

	BackupID uint64 `json:"backup_id"`
}

type RestoreBackupResponse struct {
	*WithControllerID `json:",inline"`
	Job               *Job `json:"job"`
}

type RestoreBackupJobData struct {
	BackupDatadirBeforeRestore bool   `json:"backup_datadir_before_restore"`
	BackupID                   uint64 `json:"backupid"`
	Bootstrap                  bool   `json:"bootstrap"`
}

type Backup struct {
	*WithClassName `json:",inline"`

	ID       uint64        `json:"id"`
	ParentID uint64        `json:"parent_id"`
	ChainUP  uint64        `json:"chain_up"`
	Children uint64        `json:"children"`
	Backups  []*BackupData `json:"backup"`
	Method   string        `json:"method"`
	Status   string        `json:"status"`
	Created  time.Time     `json:"created"`
	Finished time.Time     `json:"finished"`
}

// GetSize returns a sum of backup files sizes.
func (b *Backup) GetSize() int64 {
	size := int64(0)
	if b.Backups != nil {
		for _, br := range b.Backups {
			if br.Files == nil {
				continue
			}
			for _, bf := range br.Files {
				size += bf.Size
			}
		}
	}
	return size
}

type BackupData struct {
	DB        string        `json:"db"`
	Files     []*BackupFile `json:"files"`
	StartTime time.Time     `json:"start_time"`
}

type BackupFile struct {
	*WithClassName `json:",inline"`

	Created time.Time `json:"created"`
	Hash    string    `json:"hash"`
	Path    string    `json:"path"`
	Size    int64     `json:"size"`
	Type    string    `json:"type"`
}

type BackupSchedule struct {
	*WithClassName `json:",inline"`

	ClusterID  uint64         `json:"cluster_id"`
	Created    time.Time      `json:"created"`
	Enabled    bool           `json:"enabled"`
	ID         uint64         `json:"id"`
	Job        *BackupJobData `json:"job"`
	Recurrence string         `json:"recurrence"`
	Status     string         `json:"status"`
}
