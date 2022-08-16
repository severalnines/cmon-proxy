package main
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
	"encoding/json"
	"log"

	"github.com/severalnines/cmon-proxy/cmon"
	"github.com/severalnines/cmon-proxy/config"
	"github.com/severalnines/cmon-proxy/logger"
	"go.uber.org/zap"
)

// entry point. no logic here.
func main() {
	logger.New(logger.DefaultConfig())
	zap.L().Info("Tester...")

	client := cmon.NewClient(&config.CmonInstance{Url: "https://127.0.0.1:9501", Username: "kedz", Password: "password"}, 30)
	err := client.Authenticate()
	if err != nil {
		log.Println("%+v", err)
		res, err := client.Ping()
		log.Println("%+v  %+v", err, res)
		return
	}
	//      req := api.GetAllClusterInfoRequest{}
	//      req.Operation = "getAllClusterInfo"
	res, err := client.GetAllClusterInfo(nil)
	if err != nil {
		log.Println(err)
	} else {
		x, _ := json.Marshal(res)
		log.Println(string(x))
	}
}
