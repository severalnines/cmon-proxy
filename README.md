# cmon-proxy
cmon-proxy creates a unified view of multiple controllers.

Disclaimer: everything here is currently experimental, in a working progress
state.

## Configuration

The daemon expects (for now) the configuration file located in the current
working directory, its structure can be found here:
https://github.com/severalnines/cmon-proxy/blob/main/config/config.go#L22

An example configuration can be seen here:
https://github.com/severalnines/cmon-proxy/blob/main/cmon-proxy.yaml.sample

## RPC endpoints

### Controllers status

This endpoint will gives an oversview of the available configured cmon instances
and their status and version informations.

The reply structure can be found there:
https://github.com/severalnines/cmon-proxy/blob/main/proxy/api/controllerstatus.go#L24

An example request and reply:
```bash
curl -k 'https://localhost:19051/proxy/controllers/status' | jq
```

```go
{
  "controllers": [
    {
      "controller_id": "926e81d6-cfde-41f1-a36e-06280c156ca5",
      "controller_name": "lxd-cmon",
      "url": "10.216.188.149:9501",
      "version": "1.8.1.4288",
      "status_message": "",
      "status": "ok"
    },
    {
      "controller_id": "home.kedz.eu",
      "controller_name": "kedz-workstation",
      "url": "127.0.0.01:9501",
      "version": "1.8.2",
      "status_message": "",
      "status": "ok"
    },
    {
      "controller_id": "f141d8ca-cab7-4324-a940-e1df91b87489",
      "controller_name": "cmon-authfail",
      "url": "10.216.188.111:9501",
      "version": "1.8.2.999",
      "status_message": "AccessDenied: Username or password is incorrect.",
      "status": "authentication-error"
    },
    {
      "controller_id": "",
      "controller_name": "cmonoff",
      "url": "10.216.111.243:123456",
      "version": "",
      "status_message": "Post \"https://10.216.111.243:123456/v2/auth\": dial tcp: address 123456: invalid port",
      "status": "failed"
    }
  ]
}
```
