package main

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
