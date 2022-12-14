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

	ID        uint64        `json:"id"`
	ClusterID uint64        `json:"cid"`
	ParentID  uint64        `json:"parent_id"`
	ChainUP   uint64        `json:"chain_up"`
	Children  uint64        `json:"children"`
	Backups   []*BackupData `json:"backup"`
	Method    string        `json:"method"`
	Status    string        `json:"status"`
	Created   NullTime      `json:"created"`
	Finished  NullTime      `json:"finished"`
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
	StartTime NullTime      `json:"start_time"`
}

type BackupFile struct {
	*WithClassName `json:",inline"`

	Created NullTime `json:"created"`
	Hash    string   `json:"hash"`
	Path    string   `json:"path"`
	Size    int64    `json:"size"`
	Type    string   `json:"type"`
}

type BackupSchedule struct {
	*WithClassName `json:",inline"`

	ClusterID  uint64         `json:"cluster_id"`
	Created    NullTime       `json:"created"`
	Enabled    bool           `json:"enabled"`
	ID         uint64         `json:"id"`
	Job        *BackupJobData `json:"job"`
	Recurrence string         `json:"recurrence"`
	Status     string         `json:"status"`
}
