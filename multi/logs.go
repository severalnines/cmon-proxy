package multi

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
	"github.com/severalnines/cmon-proxy/multi/api"
)

// RPCLogsList returns the list of logs
func (p *Proxy) RPCLogsList(ctx *gin.Context) {
	var req api.LogListRequest

	if ctx.Request.Method == http.MethodPost {
		if err := ctx.BindJSON(&req); err != nil {
			cmonapi.CtxWriteError(ctx,
				cmonapi.NewError(cmonapi.RequestStatusInvalidRequest, fmt.Sprint("Invalid request:", err.Error())))
			return
		}
	}

	resp := &api.LogListReply{
		LastUpdated: make(map[string]*cmonapi.NullTime),
		Logs:        make([]*api.LogExt, 0),
	}

	p.Router(ctx).GetLogs(false)
	for _, url := range p.Router(ctx).Urls() {
		data := p.Router(ctx).Cmon(url)
		if data == nil || len(data.Logs) < 1 {
			continue
		}
		controllerId := data.ControllerID()
		xid := data.Xid()

		if !api.PassFilter(req.Filters, "xid", xid) ||
			!api.PassFilter(req.Filters, "controller_id", controllerId) ||
			!api.PassFilter(req.Filters, "controller_url", url) {
			continue
		}

		logs := data.Logs

		if logs[0] != nil && logs[0].WithResponseData != nil {
			resp.LastUpdated[url] = &logs[0].RequestProcessed
		}

		for cid, clusterLogs := range logs {
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
			for _, log := range clusterLogs.Logs {
				// if !api.PassFilter(req.Filters, "severity_name", alarm.SeverityName) {
				// 	continue
				// }
				// if !api.PassFilter(req.Filters, "type_name", alarm.TypeName) {
				// 	continue
				// }
				// if !api.PassFilter(req.Filters, "hostname", alarm.Hostname) {
				// 	continue
				// }
				// if !api.PassFilter(req.Filters, "component_name", alarm.ComponentName) {
				// 	continue
				// }

				resp.Add(log, url, controllerId, xid)
			}
		}
	}

	// handle sorting && pagination
	resp.Page = req.Page
	resp.PerPage = req.PerPage
	resp.Total = uint64(len(resp.Logs))
	// sort first
	order, desc := req.GetOrder()
	switch order {
	case "created":
		sort.Slice(resp.Logs[:], func(i, j int) bool {
			if desc {
				i, j = j, i
			}
			return resp.Logs[i].Created.T.Before(resp.Logs[j].Created.T)
		})
	case "cluster_id":
		sort.Slice(resp.Logs[:], func(i, j int) bool {
			if desc {
				i, j = j, i
			}
			return resp.Logs[i].LogSpecifics.ClusterID < resp.Logs[j].LogSpecifics.ClusterID
		})
	case "severity":
		sort.Slice(resp.Logs[:], func(i, j int) bool {
			if desc {
				i, j = j, i
			}
			return resp.Logs[i].Severity < resp.Logs[j].Severity
		})
	}
	if req.ListRequest.PerPage > 0 {
		// then handle the pagination
		from, to := api.Paginate(req.ListRequest, int(resp.Total))
		resp.Logs = resp.Logs[from:to]
	}

	ctx.JSON(http.StatusOK, resp)
}
