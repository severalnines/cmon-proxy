package opts

import (
	"github.com/jessevdk/go-flags"
	"go.uber.org/zap"
)

var Opts = struct {
	DebugCmonRpc bool `long:"debug-cmon-rpc" description:"Debug log RPC requests to cmon"`
	DebugWebRpc  bool `long:"debug-web-rpc" description:"Debug web RPC requests to cmon-proxy"`
}{
	DebugCmonRpc: false,
	DebugWebRpc:  false,
}

func init() {
	if _, err := flags.Parse(&Opts); err != nil {
		zap.L().Sugar().Fatalf("Failed to parse command line options: %s", err.Error())
	}
}
