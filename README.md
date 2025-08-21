# cmon-proxy

cmon-proxy creates a unified view of multiple controllers.

Disclaimer: everything here is currently experimental, in a working progress
state.

## Running with docker

NOTE: This writing assumes you have the docker image available at tag
'severalnines/clustercontrol-manager'.

Updated, it is not published/released from time-to-time to our dockerhub
(manually for now): <https://hub.docker.com/repository/docker/severalnines/clustercontrol-manager>

### Configure custom SSL certificates

Create a persistent storage directory on your host system, like ./cmon-proxy-data,
this directory will contain the configuration files and TLS certs/keys and the
log of the cmon-proxy application.
You can put your own TLS cert (a combined full chain one, so the main cert and
all the CA-s together, or just a self signed one) and key into your data
directory using the following file names: server.crt and server.key

### Start the daemon

You should pass the full path to your persistent directory to docker.
By default the service runs at 19051, you can redirect it to any freely choosen
available port.

    mkdir cmon-proxy-data
    docker run -v "$(pwd)/cmon-proxy-data:/data" -p 19051:19051 severalnines/clustercontrol-manager

At first startup you are gonna see an auto generated 'admin' user and password
printed out, you may use this or change the password or even drop this user.

### Manager local admin users

Currently the daemon stores the password hashes (PBKDF2 algo) in the
configuration file, you can manage the users using the following commands (after
u have the proxy up&running)

Lets find out your container ID/name first

    $ docker ps
    CONTAINER ID   IMAGE                     COMMAND                  CREATED         STATUS         PORTS                      NAMES
    b6eca97d4982   severalnines/cmon-proxy   "/ccmgr --basedir=/d…"   8 minutes ago   Up 8 minutes   0.0.0.0:19051->19051/tcp   cranky_chandrasekhar

Then you can use the ccmgradm tool to manage the users:

    $ docker exec b6eca97d4982 ./ccmgradm
    ClusterControl Manager - admin CLI v2.2
    Usage:  ./ccmgradm adduser|setpassword|dropuser USERNAME [PASSWORD]

Creating a user for example:

    $ docker exec b6eca97d4982 ./ccmgradm adduser myuser mypassword
    ClusterControl Manager - admin CLI v2.2
    Succeed, reloading daemon.

### Manage controllers using CLI

NOTE, new functionality, when registering controllers using LDAP authentication, you do not need
to specify any static username and password, as the the cmon-proxy frontend authentication will
be simply forwarded to the registered (and LDAP enabled) cmon instances, for example:

     ccmgradm addcontroller -l --name LDAPONE ldap.myserver.tld:9501 --frontend-url https://ldap.myserver.tld

List the currently registered controllers:

     $ ccmgradm listcontrollers
     ClusterControl Manager - admin CLI v2.2

     Controllers from configuration:
     * 127.0.0.01:9501 [kedz-workstation] Static user: admin
     * 10.216.188.149:9501 [lxd-cmon] Static user: cmononlxd
     * 10.216.188.111:9501 [cmon-authfail] Static user: authfail
     * 10.216.111.243:123456 [cmonoff] *LDAP authentication*
     * ldap.myserver.tld:9501 [LDAPONE] *LDAP authentication* Web-UI:https://ldap.myserver.tld
     * test01:9501 [Test01] Static user: cmon
     Succeed, reloading daemon.

Add or update controller (for update just use the 'updatecontroller' subcommand:

     $ ccmgradm addcontroller --help
     ClusterControl Manager - admin CLI v2.2
     Usage: main addcontroller [--use-ldap] [--username USERNAME] [--password PASSWORD] [--name NAME] [--frontend-url FRONTEND-URL] [URL]

     Positional arguments:
       URL                    The controller's RPC(v2) URL

     Options:
       --use-ldap, -l         Use LDAP login to controller
       --username USERNAME, -u USERNAME
                              Static non-LDAP credentials
       --password PASSWORD, -p PASSWORD
                              Static non-LDAP credentials
       --name NAME, -n NAME   Controller name (default: hostname from URL)
       --frontend-url FRONTEND-URL, -f FRONTEND-URL
                              The ClusterControl WEB UI URL of this controller
       --help, -h             display this help and exit

To drop a controller:

     $ ccmgradm dropcontroller --help
     ClusterControl Manager - admin CLI v2.2
   Usage: main dropcontroller [URLORNAME]

     Positional arguments:
       URLORNAME              The controller name or URL from configuration.
       --help, -h             display this help and exit

### Initialize local CMON configuration
```bash
ccmgradm init [options]

Options:
  --local-cmon            Initialize with local CMON installation
  -p, --port             Port to start the daemon on (default: 19051)
  -f, --frontend-path    Path to web UI static files
  -c, --cmon-config      CMON config file path (default: /etc/cmon.cnf)
  -u, --cmon-url         CMON URL (default: 127.0.0.1:9501)
  -s, --cmon-ssh-url     CMON SSH URL (default: 127.0.0.1:9511)
  --enable-mcc           Enable multicontroller mode
  --set                  Set arbitrary config parameters in format key=value
```

Examples:

```bash
# Initialize with local CMON
ccmgradm init --local-cmon -p 443 -f /var/www/frontend

# Initialize with custom CMON URL
ccmgradm init --local-cmon -u host.docker.internal:19501 -f /var/www/frontend

# Initialize with multicontroller mode
ccmgradm init --local-cmon --enable-mcc -f /var/www/frontend

# Initialize with nested config parameters using dot notation
ccmgradm init --set web_server.security.content_security_policy_report_only=false --set acme_enabled=true

```


## Configuration

The daemon expects (for now) the configuration file located in the current
working directory, its structure can be found here:
<https://github.com/severalnines/cmon-proxy/blob/main/config/config.go#L22>

An example configuration can be seen here:
<https://github.com/severalnines/cmon-proxy/blob/main/cmon-proxy.yaml.sample>

### Configuration ccmgr.yaml
```yaml
filename: ccmgr.yaml
instances: # List of controller
    - xid: chebjd8gfi863qqhrolg # Controller id. Generated automatically
      url: hostname:9443/api # Controller api URL
      name: Controller name
      username: admin
      password: password
      frontend_url: http://hostname:9443/ # Url of Cluster Control web interface
      cmon_ssh_host: 127.0.0.1:9511 # cmon-ssh host and port, used for web ssh console. Default for single controller - 127.0.0.1:9511
      cmon_ssh_secure: false # if true - use TLS for cmon-ssh connection
    - xid: cnoi4d3fo0o9e9m7hap0 # Controller id. Generated automatically
      # ....
timeout: 30 # request timeout in seconds. Default 30
logfile: ccmgr.log # cmon proxy log file. Default ccmgr.log
users: # Cmon proxy users, can be set via ccmgradm setpassword <username> <password>
    - username: admin
      passwordhash: <hash>
frontend_path: /app # Path to static files that cmon proxy can serve
port: 19051
tls_cert: server.crt # Default server.crt can be set from env TLS_CERTIFICATE_FILE variable
tls_key: server.key # Default server.key can be set from env TLS_KEY_FILE variable
session_ttl: 3600000000000 # Session time to live in nanoseconds. Default 1 hour
fetch_backups_days: 7 # How many days in the past cmon-proxy should look for backup data. Default is 7 days
fetch_jobs_hours: 12 # How many hours in the past cmon-proxy should look for jobs data. Default is 12 hours
single_controller: chebjd8gfi863qqhrolg # ID of single controller, if it is set - multi-controller is disabled
k8s_proxy_url: http://127.0.0.1:8080 # Kubernetes proxy URL. Default is http://127.0.0.1:8080 
kubernetes_enabled: true # Enable Kubernetes proxy. Default is true
license_proxy_url: "https://severalnines.com/service/lic.php" # URL to request demo license during registration. Default - https://severalnines.com/service/lic.php
http_port: 80 # Port for the plain HTTP server used for ACME challenges and redirection to HTTPS. Default is 80

# Let's Encrypt settings for automatic TLS certificates
acme_enabled: false # Enable Let's Encrypt. Default is false
acme_staging: false # Use Let's Encrypt staging environment. Default is false
acme_domains: [] # List of domains to obtain certificates for.
acme_email: "" # Email address for Let's Encrypt registration and notifications.
acme_cache_dir: "autocert-cache" # Directory to cache ACME certificates. Default is "autocert-cache" in the base directory.
acme_directory_url: "" # The ACME directory URL. Defaults is empty (using library pre-defined), or staging (https://acme-staging-v02.api.letsencrypt.org/directory) if acme_staging is true.
acme_accept_tos: true # Automatically accept the ACME provider's Terms of Service. Default is true.
acme_renew_before: "720h" # Renewal window before certificate expiration (a Go duration string, e.g., "720h" for 30 days). Default is 30 days (720h).
acme_host_policy_strict: false # If true, strictly enforce that certs are only issued for domains in acme_domains. Recommended for production. Default is false.
web_server:
  trusted_proxies: [] # List of trusted proxy IPs. Default is empty.
  trusted_platform: "" # Platform header for identifying client IPs (e.g., "X-Forwarded-For"). Default is empty.
  security:
    frame_deny: true # Sets X-Frame-Options to DENY. Default is true.
    sts_seconds: 31536000 # HSTS max-age in seconds. Default is 31536000 (1 year).
    sts_include_subdomains: true # Include subdomains in HSTS policy. Default is true.
    sts_preload: false # Enable HSTS preload. Default is false.
    force_sts_header: false # Force HSTS header on every response. Default is false.
    content_type_nosniff: true # Sets X-Content-Type-Options to nosniff. Default is true.
    browser_xss_filter: false # Disables the browser's XSS filter. Default is false.
    content_security_policy: "default-src 'self'; ..." # Content Security Policy. See below for details.
    content_security_policy_report_only: true # Use CSP in report-only mode. Default is true.
    referrer_policy: "strict-origin-when-cross-origin" # Referrer-Policy header. Default is "strict-origin-when-cross-origin".
    permissions_policy: "camera=(), microphone=(), geolocation=()" # Permissions-Policy header. Default is "camera=(), microphone=(), geolocation=()".
  cors:
    allow_origins: [] # List of allowed origins for CORS. Default is empty.
    allow_methods: [] # List of allowed methods for CORS. Default is empty.
    allow_headers: [] # List of allowed headers for CORS. Default is empty.
    expose_headers: [] # List of headers to expose for CORS. Default is empty.
    allow_credentials: true # Allow credentials for CORS. Default is true.
    max_age_seconds: 0 # Max age for preflight requests. Default is 0.
  gzip:
    level: 1 # Gzip compression level (1 to 9). Default is 1 (BestSpeed).
  frontend:
    nonce_replacement_files: ["index.html"] # Files to replace CSP nonce in. Default is ["index.html"].
```

### Web server: headers and simple examples

This section explains `web_server` settings in simple terms and shows what headers they add. These settings do not change the app logic; they only affect how requests are interpreted and what security headers are sent.

#### Client IP when behind proxies/CDNs

- `trusted_proxies`: list of IPs or CIDRs of your own reverse proxies/LBs (e.g., NGINX, ALB inside your VPC). This tells the server “I trust these hops to add correct forwarding headers.”
- `trusted_platform`: name of a single header your platform uses for the end-user IP (e.g., Cloudflare uses `CF-Connecting-IP`). If set, the server reads the client IP from this header.

How `trusted_proxies` works with `X-Forwarded-For` (XFF):

- XFF is a comma-separated list of addresses. Leftmost is the original client; rightmost are the most recent proxies.
- The server looks from right to left and skips any IPs that belong to your `trusted_proxies`. The first IP that is NOT trusted is treated as the real client IP.

Example:

```
X-Forwarded-For: 203.0.113.10, 198.51.100.20, 10.0.1.5
```

- Suppose your NGINX runs in `10.0.0.0/8` and is therefore trusted (`10.0.1.5` ∈ 10.0.0.0/8). The server skips `10.0.1.5` and picks `198.51.100.20` as the client IP. If `198.51.100.0/24` is also trusted, it would then pick `203.0.113.10`.

Recommended setups:

```yaml
# NGINX/ALB behind VPC: trust only your private subnets
web_server:
  trusted_proxies: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
  # trusted_platform: ""   # leave empty; server uses X-Forwarded-For safely

# Cloudflare: let Cloudflare tell us the real IP via a single header
web_server:
  trusted_platform: "CF-Connecting-IP"
  # trusted_proxies: []     # not required in this case
```

These settings do not block traffic. They only help compute the correct end‑user IP and ignore forged XFF values from the public internet.

#### HTTPS enforcement (HSTS)

Header sent (by default on HTTPS):

```
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

- `max-age=31536000`: for 1 year, the browser must only use HTTPS for this site.
- `includeSubDomains`: apply to all subdomains too.
- `preload`: opt‑in signal for browser vendors’ HSTS preload list.

Important:

- HSTS does NOT perform redirects. It tells browsers to auto‑upgrade to HTTPS and refuse HTTP after they have seen the header once over HTTPS. This app separately runs a plain HTTP server that sends a 301 redirect to HTTPS.
- By default, this system does not force the HSTS header on every response and does not enable `preload`. Enable them only when you know you need them:

```yaml
web_server:
  security:
    force_sts_header: true
    sts_preload: true
```

- HSTS Preload list: if you do want preload, you must submit your domain to the official list and meet their requirements. See [HSTS Preload submission](https://hstspreload.org).

#### MIME type sniffing protection

Header sent:

```
X-Content-Type-Options: nosniff
```

Why: Some browsers “guess” file types. If an uploaded file that looks like JavaScript is served as `text/plain` and included via `<script>`, the browser might execute it. `nosniff` tells the browser to obey the declared `Content-Type` and refuse executing if types don’t match.

#### Legacy XSS filter

- Setting: `browser_xss_filter` (default: false)
- When enabled, header sent:

```
X-XSS-Protection: 1; mode=block
```

This is for very old browsers and is generally not needed today. Recommended to keep disabled.

#### Referrer policy

Header sent (default):

```
Referrer-Policy: strict-origin-when-cross-origin
```

Meaning: send the full referrer for same‑origin navigations, and only the origin (scheme+host+port) when navigating to a different origin. This avoids leaking full paths or query strings to third parties.

#### Content Security Policy (CSP)

What it does:

- Limits where scripts, styles, images, etc. can load from.
- Supports a per‑response nonce so inline scripts can be allowed safely.
- Can run in report‑only mode while you test your policy.

How it’s applied here:

- Configure `web_server.security.content_security_policy` as a string. Use `{{nonce}}` where a nonce should appear (e.g., in `script-src`).
- For HTML files listed in `web_server.frontend.nonce_replacement_files` (default: `index.html`), the server:
  - Generates a fresh nonce per request
  - Replaces `__NONCE__` in your HTML with that nonce
  - Sends CSP header with `{{nonce}}` replaced
  - Disables caching for those HTML responses
- If `content_security_policy_report_only: true`, the header is sent as `Content-Security-Policy-Report-Only` and the directive `upgrade-insecure-requests` is removed automatically for compatibility.

Example configuration and usage:

```yaml
web_server:
  security:
    content_security_policy: "default-src 'self'; script-src 'self' 'nonce-{{nonce}}' 'strict-dynamic'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;"
    content_security_policy_report_only: true
  frontend:
    nonce_replacement_files: ["index.html"]
```

```html
<!-- index.html -->
<script nonce="__NONCE__">/* inline boot script */</script>
```

Resulting header (report‑only example):

```
Content-Security-Policy-Report-Only: default-src 'self'; script-src 'self' 'nonce-<random>' 'strict-dynamic'; style-src 'self' 'unsafe-inline'; img-src 'self' data:
```

Default policy breakdown (what each directive allows):

- `default-src 'self'`: restrict all resources to same origin unless overridden.
- `base-uri 'self'`: only allow `<base>` URLs that point to same origin.
- `object-src 'none'`: disallow plugins (Flash/Java/…).
- `frame-ancestors 'none'`: disallow embedding this app in iframes.
- `script-src 'self' 'nonce-{{nonce}}' 'strict-dynamic'`: allow scripts from same origin and inline scripts with a nonce; `strict-dynamic` lets trusted scripts load further scripts.
- `style-src 'self' 'unsafe-inline'`: allow styles from same origin and inline styles.
- `img-src 'self' data:`: allow images from same origin and data URLs.
- `font-src 'self' data:`: allow fonts from same origin and data URLs.
- `connect-src 'self' https://severalnines.piwik.pro`: allow XHR/fetch/WebSocket to same origin and analytics endpoint.
- `worker-src 'self' blob:`: allow web workers from same origin and blob URLs.
- `form-action 'self'`: only allow form submissions to same origin.
- `upgrade-insecure-requests`: tell browsers to upgrade http:// to https:// where possible (removed automatically in report‑only mode here).

#### CORS (Cross‑Origin Resource Sharing)

When to use: if your frontend (browser app) is served from a different origin (domain/port) than this API.

Configuration example:

```yaml
web_server:
  cors:
    allow_origins: ["https://ui.example.com"]
    allow_methods: ["GET", "POST", "PUT", "PATCH", "DELETE"]
    allow_headers: ["Content-Type", "Authorization"]
    expose_headers: ["X-Request-Id"]
    allow_credentials: true
    max_age_seconds: 600
```

Typical preflight (OPTIONS) response:

```
Access-Control-Allow-Origin: https://ui.example.com
Access-Control-Allow-Methods: GET,POST,PUT,PATCH,DELETE
Access-Control-Allow-Headers: Content-Type,Authorization
Access-Control-Allow-Credentials: true
Access-Control-Max-Age: 600
```


## RPC endpoints

### Authentication

During first startup the daemon is generating a default admin user and a
password, it can be found in its log file.

```
2021-03-02T14:06:11.347+0100 info Default 'admin' user has been created with password '7052369b1abd'
```

#### Login request

LoginRequest struct: <https://github.com/severalnines/cmon-proxy/blob/main/multi/api/user.go#L8>

```bash
curl -XPOST -k 'https://home.kedz.eu:19051/proxy/auth/login'  -d'{"username":"admin","password":"7052369b1abd"}' -c cookies.jar
```

```json
{
  "request_created": "",
  "request_processed": "2021-03-03T11:17:43+01:00",
  "request_status": "Ok",
  "username": {
    "username": "admin"
  }
}
```

#### Logout request

(it can be either POST or GET request)

```bash
curl -XPOST -k 'https://home.kedz.eu:19051/proxy/auth/logout'  -d'{}' -b cookies.jar
```

#### Check (get current user data) request

If user is not logged in the request will throw a 401 HTTP status

```bash
curl -XPOST -k 'https://home.kedz.eu:19051/proxy/auth/check'  -d'{}' -b cookies.jar
```

```json
{
  "request_created": "",
  "request_processed": "2021-03-03T11:18:34+01:00",
  "request_status": "Ok",
  "username": {
    "username": "admin"
  }
}
```

#### Update the user details

Updating the ProxyUser object fields (you must send all, except passwordash it
is going to be discarded by this request anyway, you can't udpate password using
this request)
ProxUser fields: <https://github.com/severalnines/cmon-proxy/blob/main/config/config.go#L23>

```bash
curl -XPOST -k 'https://home.kedz.eu:19051/proxy/auth/update'  -d'{"user":{"username":"admin","email":"kedz@kedz.eu"}}' -b cookies.jar | jq
```

```json
{
  "request_created": "",
  "request_processed": "2021-03-03T12:07:05+01:00",
  "request_status": "Ok",
  "user": {
    "username": "admin",
    "email": "kedz@kedz.eu"
  }
}
```

#### Update user password

```bash
curl -XPOST -k 'https://home.kedz.eu:19051/proxy/auth/setpassword'  -d'{"old_password":"7052369b1abd","new_password":"password"}' -b cookies.jar | jq
```

```json
{
  "request_created": "",
  "request_processed": "2021-03-03T12:10:16+01:00",
  "request_status": "Ok",
  "user": {
    "username": "kedz"
  }
}
```

### Controllers status

This endpoint will gives an overview of the available configured cmon instances
and their status and version informations.

The reply structure can be found there:
<https://github.com/severalnines/cmon-proxy/blob/main/multi/api/controllerstatus.go#L40>

You may send a POST request here, in that way it is possible to define the 'force_license_check' flag.
See <https://github.com/severalnines/cmon-proxy/blob/main/multi/api/controllerstatus.go#L36> for exact details on the request arguments.

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

- proxy/controllers/test: to test a controller (in case of LDAP it only works
  when the currently logged user is an LDAP user)
- proxy/controllers/add: to add a new controller
- proxy/controllers/update: update an existing controller

The controller parameters can be seen here: <https://github.com/severalnines/cmon-proxy/blob/main/config/config.go#L31>

```bash
curl -XPOST -k 'https://localhost:19051/proxy/controllers/test' -d'{"controller":{"url":"192.168.0.100:9501","name":"testadd","username":"someuser","password":"password"}}' | jq
````

##### for updating controller - xid needs to be used instead of url:
```bash
curl -XPOST -k 'https://localhost:19051/proxy/controllers/update' -d'{"controller":{"xid":"co163ho8ia90oenf0o2g","name":"testadd","username":"someuser","password":"password"}}' | jq
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
##### Note - removing controller requires using xid, not url

```bash
curl -XPOST -k 'https://localhost:19051/proxy/controllers/remove' -d'{"xid":"co163ho8ia90oenf0o2g"}' | jq
```

```json
{
  "type": "Ok",
  "message": "The controller is removed."
}
```

### Clusters status overview

```bash
curl -k -XPOST 'https://localhost:19051/proxy/clusters/status' -d'{"filters":[{"key":"tags", "matchall":["test","bitcoin"]}]}' | jq
```

Returned fields:

- "cluster_states": count of clusters in certain cluster state
- "node_states": count of node states in certain host status
- "clusters_count": the number of clusters hosted by each controller (key is cmon URL)
- "nodes_count": the number of hosts by each controller (key is cmon URL)

The possible cluster states are:

- CLUSTER_MGMD_NO_CONTACT: No contact to the management node.
- CLUSTER_STARTED: There are no failed nodes, there are started nodes.
- CLUSTER_NOT_STARTED: The cluster is failed to start.
- CLUSTER_DEGRADED: There are running and there are failed nodes as well.
- CLUSTER_FAILURE: Cluster is failed to start.
- CLUSTER_SHUTTING_DOWN: Cluster is stopping now.
- CLUSTER_RECOVERING: Cluster is recovering from an error.
- CLUSTER_STARTING: Cluster is starting.
- CLUSTER_UNKNOWN: Cluster state is not yet determined.
- CLUSTER_STOPPED: The cluster is stopped by Cmon.

The possible host states are ( also see <https://severalnines.com/downloads/cmon/cmon-docs/current/hosts.html> ):

- CmonHostUnknown: The status of the host is not yet found.
- CmonHostOnline: The host is on-line, everything is ok with it, no errors or special conditions detected.
- CmonHostOffLine: The host is off-line, can not be contacted and we have no detailed information about what happened.
- CmonHostFailed: We have a connection to the host, but it is failed. We already know that the controller can not recover the host, manual intervention is required.
- CmonHostRecovery: There was some error and the host is now recovering.
- CmonHostShutDown: The host is deliberately shut down.

Reply definition: <https://github.com/severalnines/cmon-proxy/blob/main/multi/api/clustersoverview.go>

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
  },
  "by_controller": {
    "cfqb3bv6i1eb2e2qsrig": {
      "cluster_states": {
          "STARTED": 4
      },
      "node_states": {
          "CmonHostOnline": 21
      },
      "by_cluster": {
        "1": {
            "node_states": {
                "CmonHostOnline": 6
            }
        },
        "2": {
            "node_states": {
                "CmonHostOnline": 3
            }
        },
        "3": {
            "node_states": {
                "CmonHostOnline": 10
            }
        },
        "4": {
            "node_states": {
                "CmonHostOnline": 2
            }
        }
      }
    },
    "cgimqin6i1e1gkrk3700": {
      "cluster_states": {
          "STARTED": 3
      },
      "node_states": {
          "CmonHostOnline": 15
      },
      "by_cluster": {
        "1": {
            "node_states": {
                "CmonHostOnline": 3
            }
        },
        "2": {
            "node_states": {
                "CmonHostOnline": 3
            }
        },
        "3": {
            "node_states": {
                "CmonHostOnline": 9
            }
        }
      }
    }
  }
}
```

### Clusters list

Request/reply structure: <https://github.com/severalnines/cmon-proxy/blob/main/multi/api/clusterlist.go>

*PAGINATION* and sorting is possible, see ListRequest at <https://github.com/severalnines/cmon-proxy/blob/main/multi/api/common.go>

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

Request/reply structure: <https://github.com/severalnines/cmon-proxy/blob/main/multi/api/hostlist.go>

*PAGINATION* and sorting is possible, see ListRequest at <https://github.com/severalnines/cmon-proxy/blob/main/multi/api/common.go>

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
curl -k 'https://localhost:19051/proxy/alarms/status' | jq
```

```json
{
  "alarms_count": {
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
      "alarms_count": {
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

### Alarms list

Request/reply structure: <https://github.com/severalnines/cmon-proxy/blob/main/multi/api/alarms.go>

*PAGINATION* and sorting is possible, see ListRequest at <https://github.com/severalnines/cmon-proxy/blob/main/multi/api/common.go>

Supported filter keys for this request: controller_id, controller_url,
cluster_id, cluster_type, severity_name, type_name, hostname, component_name,
tags

```bash
$ curl -XPOST -k 'https://localhost:19051/proxy/alarms/list' \
    -d'{"filters":[ {"key":"severity_name","value":"ALARM_WARNING"} ]}' | jq
```

```json
{
  "alarms": [
    {
      "controller_id": "home.kedz.eu",
      "controller_url": "127.0.0.01:9501",
      "alarm_id": 13752,
      "cluster_id": 248,
      "component_name": "Cluster",
      "created": "2020-12-17T13:32:41Z",
      "hostname": "",
      "title": "Cluster Failure",
      "message": "Cluster Failure.",
      "recommendation": "Cluster failed, Cluster Recovery needed.",
      "severity_name": "ALARM_WARNING",
      "type_name": "ClusterFailure"
    }
  ],
  "last_updated": {
    "10.216.188.149:9501": "2020-12-16T15:06:55Z",
    "127.0.0.01:9501": "2020-12-16T15:06:55Z"
  }
}
```

### Jobs status

```bash
curl -XPOST -k 'https://home.kedz.eu:19051/proxy/jobs/status'  -d'{"filters":[]}' | jq
```

```json
{
  "job_count": {
    "FAILED": 1,
    "FINISHED": 8
  },
  "job_commands": {
    "backup": 9
  },
  "by_controller": {
    "10.216.188.149:9501": {
      "job_count": {},
      "job_commands": {}
    },
    "127.0.0.01:9501": {
      "job_count": {
        "FAILED": 1,
        "FINISHED": 8
      },
      "job_commands": {
        "backup": 9
      }
    }
  },
  "by_cluster_type": {
    "POSTGRESQL_SINGLE": {
      "job_count": {
        "FINISHED": 1
      },
      "job_commands": {
        "backup": 1
      },
      "by_controller": {
        "127.0.0.01:9501": {
          "job_count": {
            "FINISHED": 1
          },
          "job_commands": {
            "backup": 1
          }
        }
      }
    },
    "REPLICATION": {
      "job_count": {
        "FAILED": 1,
        "FINISHED": 7
      },
      "job_commands": {
        "backup": 8
      },
      "by_controller": {
        "127.0.0.01:9501": {
          "job_count": {
            "FAILED": 1,
            "FINISHED": 7
          },
          "job_commands": {
            "backup": 8
          }
        }
      }
    }
  }
}
```

### Jobs list

Request/reply structure: <https://github.com/severalnines/cmon-proxy/blob/main/multi/api/jobs.go>

*PAGINATION* and sorting is possible, see ListRequest at <https://github.com/severalnines/cmon-proxy/blob/main/multi/api/common.go>

Supported filter keys for this request: controller_id, controller_url,
cluster_id, cluster_type, job_command, tags

```bash
curl -XPOST -k 'https://localhost:19051/proxy/alarms/list' | jq
```

```json
{
  "jobs": [
    {
      "controller_id": "home.kedz.eu",
      "controller_url": "127.0.0.01:9501",
      "class_name": "CmonJobInstance",
      "tags": [
        "recurrence"
      ],
      "cluster_id": 215,
      "user_id": 0,
      "user_name": "system",
      "group_id": 1,
      "group_name": "admins",
      "can_be_deleted": true,
      "created": "2021-02-02T13:50:00Z",
      "ended": "2021-02-02T13:50:11Z",
      "ip_address": "127.0.0.1",
      "job_id": 185319,
      "parent_job_id": 94935,
      "rpc_version": "1.0",
      "started": "2021-02-02T13:50:02Z",
      "status": "FINISHED",
      "status_text": "Command ok",
      "title": "Create Backup",
      "job_spec": {
        "command": "backup",
        "job_data": {
          "backup_failover": false,
          "backup_failover_host": "10.216.188.231:3306",
          "backup_method": "mariabackupincr",
          "backup_retention": 0,
          "backupdir": "/home/cmon_user/backups",
          "backupsubdir": "BACKUP-%I",
          "cc_storage": "0",
          "compression": true,
          "compression_level": 6,
          "hostname": "auto",
          "throttle_rate_netbw": 0,
          "use_pigz": false,
          "use_qpress": false,
          "wsrep_desync": false,
          "xtrabackup_backup_locks": true,
          "xtrabackup_lock_ddl_per_table": false,
          "xtrabackup_parallellism": 1
        }
      },
      "has_progress": false,
      "progress_percent": 0
    },
 /* ... */
  ],
  "last_updated": {
    "10.216.188.149:9501": "2020-12-16T15:06:55Z",
    "127.0.0.01:9501": "2020-12-16T15:06:55Z"
  }
}
```

### Backup status overview

Reply definition: <https://github.com/severalnines/cmon-proxy/blob/main/multi/api/backups.go>

NOTE: tag filtration is possible

```bash
curl -k -XPOST 'https://localhost:19051/proxy/backups/status' -d'{}' | jq
```

```json
{
  "backups_count": {
    "Completed": 11,
    "Failed": 2
  },
  "by_controller": {
    "10.216.111.243:123456": {
      "backups_count": {},
      "missing_schedules": 0,
      "schedules_count": 0
    },
    /* ... */
  }
  /* ... */
}
```

### Backup schedules list

Request/reply structure: <https://github.com/severalnines/cmon-proxy/blob/main/multi/api/jobs.go>

*PAGINATION* and sorting is possible, see ListRequest at <https://github.com/severalnines/cmon-proxy/blob/main/multi/api/common.go>

Supported filter keys for this request: controller_id, controller_url,
cluster_id, cluster_type, tags

```bash
curl -XPOST -k 'https://home.kedz.eu:19051/proxy/backups/schedules'  -d'{"{filters":[{"cluster_id": 234}]}' | jq
```

The reply is the same as in case of jobs list, but this one returns only the
scheduled backup jobs only

```json
{
  "jobs": [
    /* ... */
  ],
  "last_updated": {
    /* ... */
  }
}
```

### Backups list

Request/reply structure: <https://github.com/severalnines/cmon-proxy/blob/main/multi/api/backups.go>

*PAGINATION* and sorting is possible, see ListRequest at <https://github.com/severalnines/cmon-proxy/blob/main/multi/api/common.go>

Supported filter keys for this request: controller_id, controller_url,
cluster_id, cluster_type, tags, backup_id, status, method

```bash
curl -XPOST -k 'https://home.kedz.eu:19051/proxy/backups/schedules'  -d'{"{filters":[{"cluster_id": 234}]}' | jq
```

```json
{
  "total": 12,
  "backups": [
    {
      "controller_id": "home.kedz.eu",
      "controller_url": "127.0.0.01:9501",
      "class_name": "CmonBackupRecord",
     /* ... */
    }
  ]
}
```

## Development Setup

To set up a local development environment for cmon-proxy, follow these steps:

### Prerequisites

Install Go version 1.22 or later. You can download it from [https://golang.org/dl/](https://golang.org/dl/).

### Install Dependencies

Clone the repository and install the required dependencies:

```bash
go mod download
```

### Run the Application

To run the application with debug logging for development:

```bash
LOG_LEVEL=debug go run -tags=dev main.go
```

This command will:
- Set the log level to debug for verbose output
- Use the `dev` build tags which configure the application for local development
- Start the application on the default port (19051)

The application will create a self-signed TLS certificate automatically and be accessible at `https://localhost:19051`.

### Debug builds on MacOS

Create builder
```bash
make builder
```

Run builder
```bash
make builder-run
```
Navigate to codebase
```bash
cd /code
```

Create builds 
```bash
make ci
```

Create packages
```bash
make packages
```
