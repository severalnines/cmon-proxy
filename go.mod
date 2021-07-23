module github.com/severalnines/cmon-proxy

go 1.15

require (
	github.com/gin-contrib/sessions v0.0.3
	github.com/gin-contrib/zap v0.0.1
	github.com/gin-gonic/gin v1.7.1
	github.com/jessevdk/go-flags v1.4.0
	github.com/rs/xid v1.3.0
	github.com/severalnines/ccx v1.16.5
	go.uber.org/zap v1.16.0
	golang.org/x/crypto v0.0.0-20210421170649-83a5a9bb288b
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b
)

// replace github.com/severalnines/bar-user-auth-api => ../bar-user-auth-api
