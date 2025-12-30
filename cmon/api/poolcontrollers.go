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

type GetControllersRequest struct {
	*WithOperation `json:",inline"`
	ControllerID   int `json:"controller_id,omitempty"` // Use int instead of string
}

type GetControllersResponse struct {
	*WithControllerID `json:",inline"`
	*WithPoolId       `json:",inline"`
	*WithResponseData `json:",inline"`

	FullControllerID string            `json:"full_controller_id"`
	Total           int               `json:"total"`
	Controllers     []*PoolController `json:"controllers"`
	DebugMessages   []string          `json:"debug_messages"`
}

type PoolControllerStats struct {
	CpuPct  string `json:"cpu_pct"`
	MemUsed string `json:"mem_used"`
	MemTotal string `json:"mem_total"`
	FdUsed  int    `json:"fd_used"`
	FdTotal int    `json:"fd_total"`
}

type PoolControllerProperties struct {
	Role  string              `json:"role"` // "main_controller" or "nfs_member"
	Stats *PoolControllerStats `json:"stats,omitempty"`
}

type PoolController struct {
	ControllerID int                       `json:"controller_id"`
	Hostname     string                    `json:"hostname"`
	Port         int                       `json:"port"`
	Properties   *PoolControllerProperties `json:"properties"`
	ReportTs     string                    `json:"report_ts"`
	Status       string                    `json:"status"`
	Clusters     []string                  `json:"clusters"`
}