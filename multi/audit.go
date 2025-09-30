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

// RPCAuditEntryList returns the list of audit entries
func (p *Proxy) RPCAuditEntryList(ctx *gin.Context) {
	var req api.AuditEntryListRequest

	if ctx.Request.Method == http.MethodPost {
		if err := ctx.BindJSON(&req); err != nil {
			cmonapi.CtxWriteError(ctx,
				cmonapi.NewError(cmonapi.RequestStatusInvalidRequest, fmt.Sprint("Invalid request:", err.Error())))
			return
		}
	}

	resp := &api.AuditEntryListReply{
		LastUpdated: make(map[string]*cmonapi.NullTime),
		Entries:     make([]*api.AuditEntryExt, 0),
	}

	p.Router(ctx).GetAuditEntries(false)
	for _, url := range p.Router(ctx).Urls() {
		data := p.Router(ctx).Cmon(url)
		if data == nil {
			continue
		}
		entriesMap, controllerId, xid := p.resolveAuditEntriesSource(ctx, data)

		if !api.PassFilter(req.Filters, "xid", xid) ||
			!api.PassFilter(req.Filters, "controller_id", controllerId) ||
			!api.PassFilter(req.Filters, "controller_url", url) {
			continue
		}

		// lastUpdated best-effort: take any entry's RequestProcessed
		for _, v := range entriesMap {
			if v != nil && v.WithResponseData != nil {
				resp.LastUpdated[url] = &v.RequestProcessed
				break
			}
		}

		for cid, clusterAuditEntries := range entriesMap {
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
			for _, entry := range clusterAuditEntries.AuditEntries {
				resp.Add(entry, url, controllerId, xid)
			}
		}
	}

	// handle sorting && pagination
	resp.Page = req.Page
	resp.PerPage = req.PerPage
	resp.Total = uint64(len(resp.Entries))
	// sort first
	order, desc := req.GetOrder()
	switch order {
	case "report_ts":
		sort.Slice(resp.Entries[:], func(i, j int) bool {
			if desc {
				i, j = j, i
			}
			return resp.Entries[i].ReportTs.T.Before(resp.Entries[j].ReportTs.T)
		})
	case "cluster_id":
		sort.Slice(resp.Entries[:], func(i, j int) bool {
			if desc {
				i, j = j, i
			}
			return resp.Entries[i].ClusterID < resp.Entries[j].ClusterID
		})
	case "entry_type":
		sort.Slice(resp.Entries[:], func(i, j int) bool {
			if desc {
				i, j = j, i
			}
			return resp.Entries[i].EntryType < resp.Entries[j].EntryType
		})

	}
	if req.ListRequest.PerPage > 0 {
		// then handle the pagination
		from, to := api.Paginate(req.ListRequest, int(resp.Total))
		resp.Entries = resp.Entries[from:to]
	}

	ctx.JSON(http.StatusOK, resp)
}
