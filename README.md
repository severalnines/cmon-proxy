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

```json
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

### Test or add controller

Test or add a controller, add will cause the configuration file to be updated as
well (even in case of failures), so you might want to test first

URLS:
- proxy/controllers/test: to test a controller
- proxy/controllers/add: to add a new controller

```bash
$ curl -XPOST -k 'https://localhost:19051/proxy/controllers/test' -d'{"controller":{"url":"192.168.0.100:9501","name":"testadd","username":"someuser","password":"password"}}' | jq
````

```json
{
  "controller": {
    "controller_id": "",
    "controller_name": "testadd",
    "url": "192.168.0.100:9501",
    "version": "",
    "status_message": "Post \"https://192.168.0.100:9501/v2/auth\": dial tcp 192.168.0.100:9501: connect: connection refused",
    "status": "failed"
  }
}
```

### Remove a controller

This method can be used to remove a controller. Note the configuration will be
updated too.

```bash
$ curl -XPOST -k 'https://localhost:19051/proxy/controllers/remove' -d'{"url":"192.168.0.100:9501"}' | jq
```

```json
{
  "type": "Ok",
  "message": "The controller is removed."
}
```

### Clusters status overview

```bash
$ curl -k 'https://localhost:19051/proxy/clusters/status' | jq
```

Returned fields:
- "cluster_states": count of clusters in certain cluster state
- "node_states": count of node states in certain host status
- "clusters_count": the number of clusters hosted by each controller (key is cmon URL)
- "nodes_count": the number of hosts by each controller (key is cmon URL)

For cluster states see https://github.com/severalnines/clustercontrol-enterprise/blob/master/src/cmoncluster.cpp#L3924
For host states see https://intra.severalnines.com/cmon-docs/current/hosts.html

Reply definition: https://github.com/severalnines/cmon-proxy/blob/main/proxy/api/clustersoverview.go
```json
{
  "cluster_states": {
    "DEGRADED": 1,
    "STARTED": 47
  },
  "clusters_count": {
    "10.216.188.149:9501": 1,
    "127.0.0.01:9501": 47
  },
  "nodes_count": {
    "10.216.188.149:9501": 2,
    "127.0.0.01:9501": 189
  },
  "node_states": {
    "CmonHostOnline": 190,
    "CmonHostShutDown": 1
  }
}
```

### Clusters list

Request/reply structure: https://github.com/severalnines/cmon-proxy/blob/main/proxy/api/clusterlist.go

Supported filter keys for this request: controller_id, controller_url,
cluster_id, state, cluster_type

```bash
$ curl -XPOST -k 'https://localhost:19051/proxy/clusters/list' \
  -d'{ "filters":[ {"key":"state","values":["DEGRADED","FAILURE"] }], "with_hosts": false }' | jq
```

```json
{
  "clusters": [
    {
      "controller_id": "home.kedz.eu",
      "controller_url": "127.0.0.01:9501",
      "class_name": "CmonClusterInfo",
      "cluster_id": 262,
      "cluster_name": "cluster_262",
      "cluster_type": "POSTGRESQL_SINGLE",
      "hosts": null,
      "state": "DEGRADED",
      "maintenance_mode_active": false
    }
  ],
  "last_updated": {
    "10.216.188.149:9501": "0001-01-01T00:00:00Z",
    "127.0.0.01:9501": "0001-01-01T00:00:00Z"
  }
}
```

### Hosts list

Request/reply structure: https://github.com/severalnines/cmon-proxy/blob/main/proxy/api/hostlist.go

Supported filter keys for this request: controller_id, controller_url,
cluster_id, clusterid (yeah both as CmonHost has 'clusterid'), cluster_type,
port, hostname, role, nodetype, hoststatus

```bash
$ curl -XPOST -k 'https://localhost:19051/proxy/clusters/hosts' \
    -d'{ "filters":[ {"key":"hoststatus","values":["CmonHostOffline","CmonHostShutDown","CmonHostFailed"] }] }' | jq
```

```json
{
  "hosts": [
    {
      "controller_id": "home.kedz.eu",
      "controller_url": "127.0.0.01:9501",
      "class_name": "CmonPostgreSqlHost",
      "clusterid": 262,
      "service_started": 1607280181,
      "hostId": 5240,
      "unique_id": 880,
      "lastseen": 1608131196,
      "port": 5432,
      "listening_port": 0,
      "hostname": "10.216.188.135",
      "hoststatus": "CmonHostShutDown",
      "role": "slave",
      "nodetype": "postgres",
      "ip": "10.216.188.135",
      "rw_port": 0,
      "ro_port": 0,
      "uptime": 758329,
      "ssl_certs": {
        "replication": null,
        "server": {
          "ca": "/etc/ssl/postgresql_single/cluster_262/server_ca.crt",
          "id": 102,
          "key": "/etc/ssl/postgresql_single/cluster_262/server.key",
          "path": "/etc/ssl/postgresql_single/cluster_262/server.crt",
          "ssl_enabled": true
        }
      }
    }
  ],
  "last_updated": {
    "10.216.188.149:9501": "2020-12-16T15:06:55Z",
    "127.0.0.01:9501": "2020-12-16T15:06:55Z"
  }
}
```

### Alarms overview

```bash
$ curl -k 'https://localhost:19051/proxy/alarms/status' | jq
```

```json
{
  "alarm_counts": {
    "ALARM_WARNING": 2
  },
  "alarm_types": {
    "BackupFailed": 1,
    "HostCpuUsage": 1
  },
  "by_controller": {
    "10.216.188.149:9501": {
      "alarm_counts": {},
      "alarm_types": {}
    },
    "127.0.0.01:9501": {
      "alarm_counts": {
        "ALARM_WARNING": 2
      },
      "alarm_types": {
        "BackupFailed": 1,
        "HostCpuUsage": 1
      }
    }
  }
}
```


