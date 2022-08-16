package opts
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
	"github.com/jessevdk/go-flags"
	"go.uber.org/zap"
)

var Opts = struct {
	DebugCmonRpc bool   `long:"debug-cmon-rpc" description:"Debug log RPC requests to cmon"`
	DebugWebRpc  bool   `long:"debug-web-rpc" description:"Debug web RPC requests to cmon-proxy"`
	BaseDir      string `long:"basedir" description:"The basedir of configuration"`
}{
	DebugCmonRpc: false,
	DebugWebRpc:  false,
	BaseDir:      ".",
}

func Init() {
	if _, err := flags.Parse(&Opts); err != nil {
		zap.L().Sugar().Fatalf("Failed to parse command line options: %s", err.Error())
	}
}
