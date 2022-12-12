package proxy

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
	"sort"

	"github.com/gin-gonic/gin"
	cmonapi "github.com/severalnines/cmon-proxy/cmon/api"
	"github.com/severalnines/cmon-proxy/proxy/api"
)

// RPCAlarmsOverview gives a high level overview of all cluster alarms
func (p *Proxy) RPCAlarmsOverview(ctx *gin.Context) {
	var req api.SimpleFilteredRequest

	if ctx.Request.Method == http.MethodPost {
		if err := ctx.BindJSON(&req); err != nil {
			cmonapi.CtxWriteError(ctx,
				cmonapi.NewError(cmonapi.RequestStatusInvalidRequest,
					fmt.Sprint("Invalid request:", err.Error())))
			return
		}
	}

	resp := &api.AlarmsOverview{
		AlarmCounts:             make(map[string]int),
		AlarmTypes:              make(map[string]int),
		AlarmCountsByController: make(map[string]*api.AlarmsOverview),
		ByClusterType:           make(map[string]*api.AlarmsOverview),
	}

	p.Router(ctx).GetAlarms(false)
	for _, url := range p.Router(ctx).Urls() {
		data := p.Router(ctx).Cmon(url)
		if data == nil || data.Clusters == nil {
			continue
		}

		countsByCtrl := &api.AlarmsOverview{
			AlarmCounts: make(map[string]int),
			AlarmTypes:  make(map[string]int),
		}
		// iterate by clusterIds... one by one..
		for cid, clusterAlarms := range data.Alarms {
			// tags filtration is possible here too
			fn := func() []string { return data.ClusterTags(cid) }
			if !api.PassTagsFilterLazy(req.Filters, fn) {
				continue
			}

			clusterType := data.ClusterType(cid)
			if stat, found := resp.ByClusterType[clusterType]; !found || stat == nil {
				resp.ByClusterType[clusterType] =
					&api.AlarmsOverview{
						AlarmCounts:             make(map[string]int),
						AlarmTypes:              make(map[string]int),
						AlarmCountsByController: make(map[string]*api.AlarmsOverview),
					}
			}

			if x, found := resp.ByClusterType[clusterType].AlarmCountsByController[url]; !found || x == nil {
				resp.ByClusterType[clusterType].AlarmCountsByController[url] =
					&api.AlarmsOverview{
						AlarmCounts: make(map[string]int),
						AlarmTypes:  make(map[string]int),
					}
			}

			for _, alarm := range clusterAlarms.Alarms {
				if alarm == nil {
					// sometimes cmon returns null alarm in the list
					// this should just protect from panics
					continue
				}

				resp.AlarmCounts[alarm.SeverityName]++
				resp.AlarmTypes[alarm.TypeName]++

				resp.ByClusterType[clusterType].AlarmCounts[alarm.SeverityName]++
				resp.ByClusterType[clusterType].AlarmTypes[alarm.TypeName]++

				countsByCtrl.AlarmCounts[alarm.SeverityName]++
				countsByCtrl.AlarmTypes[alarm.TypeName]++

				resp.ByClusterType[clusterType].AlarmCountsByController[url].AlarmCounts[alarm.SeverityName]++
				resp.ByClusterType[clusterType].AlarmCountsByController[url].AlarmTypes[alarm.TypeName]++
			}
		}

		resp.AlarmCountsByController[url] = countsByCtrl
	}

	ctx.JSON(http.StatusOK, resp)
}

// RPCAlarmsList returns the list of alarms
func (p *Proxy) RPCAlarmsList(ctx *gin.Context) {
	var req api.AlarmListRequest

	if ctx.Request.Method == http.MethodPost {
		if err := ctx.BindJSON(&req); err != nil {
			cmonapi.CtxWriteError(ctx,
				cmonapi.NewError(cmonapi.RequestStatusInvalidRequest, fmt.Sprint("Invalid request:", err.Error())))
			return
		}
	}

	resp := &api.AlarmListReply{
		LastUpdated: make(map[string]*cmonapi.NullTime),
		Alarms:      make([]*api.AlarmExt, 0),
	}

	p.Router(ctx).GetAlarms(false)
	for _, url := range p.Router(ctx).Urls() {
		data := p.Router(ctx).Cmon(url)
		if data == nil || len(data.Alarms) < 1 {
			continue
		}
		controllerId := data.ControllerID()

		if !api.PassFilter(req.Filters, "controller_id", controllerId) ||
			!api.PassFilter(req.Filters, "controller_url", url) {
			continue
		}

		alarms := data.Alarms

		if alarms[0] != nil && alarms[0].WithResponseData != nil {
			resp.LastUpdated[url] = &alarms[0].RequestProcessed
		}

		for cid, clusterAlarms := range alarms {
			if !api.PassFilter(req.Filters, "cluster_id", fmt.Sprintf("%d", cid)) {
				continue
			}
			if !api.PassFilterLazy(req.Filters, "cluster_type",
				func() string { return data.ClusterType(cid) }) {
				continue
			}
			fn := func() []string { return data.ClusterTags(cid) }
			if !api.PassTagsFilterLazy(req.Filters, fn) {
				continue
			}
			for _, alarm := range clusterAlarms.Alarms {
				if !api.PassFilter(req.Filters, "severity_name", alarm.SeverityName) {
					continue
				}
				if !api.PassFilter(req.Filters, "type_name", alarm.TypeName) {
					continue
				}
				if !api.PassFilter(req.Filters, "hostname", alarm.Hostname) {
					continue
				}
				if !api.PassFilter(req.Filters, "component_name", alarm.ComponentName) {
					continue
				}

				resp.Add(alarm, url, controllerId)
			}
		}
	}

	// handle sorting && pagination
	resp.Page = req.Page
	resp.PerPage = req.PerPage
	resp.Total = uint64(len(resp.Alarms))
	// sort first
	order, desc := req.GetOrder()
	switch order {
	case "created":
		sort.Slice(resp.Alarms[:], func(i, j int) bool {
			if desc {
				i, j = j, i
			}
			return resp.Alarms[i].ClusterId < resp.Alarms[j].ClusterId
		})
	case "cluster_id":
		sort.Slice(resp.Alarms[:], func(i, j int) bool {
			if desc {
				i, j = j, i
			}
			return resp.Alarms[i].ClusterId < resp.Alarms[j].ClusterId
		})
	case "severity_name":
		sort.Slice(resp.Alarms[:], func(i, j int) bool {
			if desc {
				i, j = j, i
			}
			return resp.Alarms[i].SeverityName < resp.Alarms[j].SeverityName
		})
	case "type_name":
		sort.Slice(resp.Alarms[:], func(i, j int) bool {
			if desc {
				i, j = j, i
			}
			return resp.Alarms[i].TypeName < resp.Alarms[j].TypeName
		})
	case "hostname":
		sort.Slice(resp.Alarms[:], func(i, j int) bool {
			if desc {
				i, j = j, i
			}
			return resp.Alarms[i].Hostname < resp.Alarms[j].Hostname
		})
	case "component_name":
		sort.Slice(resp.Alarms[:], func(i, j int) bool {
			if desc {
				i, j = j, i
			}
			return resp.Alarms[i].ComponentName < resp.Alarms[j].ComponentName
		})
	}
	if req.ListRequest.PerPage > 0 {
		// then handle the pagination
		from, to := api.Paginate(req.ListRequest, int(resp.Total))
		resp.Alarms = resp.Alarms[from:to]
	}

	ctx.JSON(http.StatusOK, resp)
}
