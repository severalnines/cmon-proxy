package api


type ConfigExt struct {
	FetchBackupsDays *int `json:"fetch_backups_days,omitempty"`
	FetchJobsHours *int `json:"fetch_jobs_hours,omitempty"`
}

type ConfigResponse struct {
	Config ConfigExt `json:"config"`
}

type ConfigRequest struct {
}