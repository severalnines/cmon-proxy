package proxy

import (
	"fmt"
	"net/http"

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
		Alarms:      make([]*api.AlarmExt, 0, 16),
		LastUpdated: make(map[string]*cmonapi.NullTime),
	}

	p.r.GetAlarms(false)
	for _, url := range p.r.Urls() {
		data := p.r.Cmon(url)
		if data == nil || len(data.Alarms) < 1 {
			continue
		}
		if !api.PassFilter(req.Filters, "controller_id", data.ControllerID()) ||
			!api.PassFilter(req.Filters, "controller_url", url) {
			continue
		}

		alarms := data.Alarms

		resp.LastUpdated[url] = &cmonapi.NullTime{
			T: alarms[0].RequestProcessed,
		}

		/*
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
		*/
	}

	ctx.JSON(http.StatusOK, resp)
}
