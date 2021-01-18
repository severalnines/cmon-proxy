package proxy

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
	//logger := zap.L()

	resp := &api.AlarmsOverview{
		AlarmCounts:             make(map[string]int),
		AlarmTypes:              make(map[string]int),
		AlarmCountsByController: make(map[string]*api.AlarmsOverview),
	}

	p.r.GetAlarms(false)
	for _, url := range p.r.Urls() {
		data := p.r.Cmon(url)
		if data == nil || data.Clusters == nil {
			continue
		}

		countsByCtrl := &api.AlarmsOverview{
			AlarmCounts: make(map[string]int),
			AlarmTypes:  make(map[string]int),
		}
		// iterate by clusterIds... one by one..
		for _, clusterAlarms := range data.Alarms {
			for _, alarm := range clusterAlarms.Alarms {
				resp.AlarmCounts[alarm.SeverityName]++
				resp.AlarmTypes[alarm.TypeName]++

				countsByCtrl.AlarmCounts[alarm.SeverityName]++
				countsByCtrl.AlarmTypes[alarm.TypeName]++
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
	}

	p.r.GetAlarms(false)
	for _, url := range p.r.Urls() {
		data := p.r.Cmon(url)
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
			resp.LastUpdated[url] = &cmonapi.NullTime{
				T: alarms[0].RequestProcessed,
			}
		}

		for cid, clusterAlarms := range alarms {
			if !api.PassFilter(req.Filters, "cluster_id", fmt.Sprintf("%d", cid)) {
				continue
			}
			if !api.PassFilterLazy(req.Filters, "cluster_type",
				func() string { return data.ClusterType(cid) }) {
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
	switch req.Order {
	case "cluster_id":
		sort.Slice(resp.Alarms[:], func(i, j int) bool {
			return resp.Alarms[i].ClusterId < resp.Alarms[j].ClusterId
		})
	case "severity_name":
		sort.Slice(resp.Alarms[:], func(i, j int) bool {
			return resp.Alarms[i].SeverityName < resp.Alarms[j].SeverityName
		})
	case "type_name":
		sort.Slice(resp.Alarms[:], func(i, j int) bool {
			return resp.Alarms[i].TypeName < resp.Alarms[j].TypeName
		})
	case "hostname":
		sort.Slice(resp.Alarms[:], func(i, j int) bool {
			return resp.Alarms[i].Hostname < resp.Alarms[j].Hostname
		})
	case "component_name":
		sort.Slice(resp.Alarms[:], func(i, j int) bool {
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
