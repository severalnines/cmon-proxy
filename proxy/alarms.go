package proxy

import (
	"net/http"

	"github.com/gin-gonic/gin"
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
