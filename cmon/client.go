package cmon

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
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/severalnines/cmon-proxy/cmon/api"
	"github.com/severalnines/cmon-proxy/config"
	"github.com/severalnines/cmon-proxy/opts"
	"go.uber.org/zap"
)

const (
	connectionTimeout = 3 * time.Second
)

// Client struct.
type Client struct {
	Instance          *config.CmonInstance
	http              *http.Client
	ses               *http.Cookie
	mtx               *sync.Mutex
	user              *api.User
	controllerID      string // the controllerID obtained from the replies
	lastRequestStatus string // the last request status
	serverVersion     string // the server version obtained from the headers
}

// NewClient returns a new RPCv2 client.
func NewClient(instance *config.CmonInstance, timeout int) *Client {
	httpClient := &http.Client{
		Timeout: time.Second * time.Duration(timeout),
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout: connectionTimeout,
			}).DialContext,
			TLSHandshakeTimeout: connectionTimeout,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	c := &Client{
		Instance: instance,
		http:     httpClient,
		mtx:      &sync.Mutex{},
	}
	return c
}

// Request does an RPCv2 request to cmon. It authenticates and re-authenticates automatically.
func (client *Client) RequestBytes(module string, reqBytes []byte, noAutoAuth ...bool) (resBytes []byte, err error) {
	// for regular requests we may want to auto reauthenticate
	autoAuth := len(noAutoAuth) < 1 || !noAutoAuth[0]
	client.lastRequestStatus = ""

	if autoAuth && client.ses == nil {
		if err := client.Authenticate(); err != nil {
			return nil, err
		}
	}
	uri := client.buildURI(module)
	request, err := http.NewRequest(
		http.MethodPost,
		uri,
		bytes.NewBuffer(reqBytes))
	if err != nil {
		return nil, err
	}

	if opts.Opts.DebugCmonRpc {
		zap.L().Sugar().Debugf("Request to cmon %s:\n%s",
			uri, string(reqBytes))
	}

	if client.ses != nil {
		request.Header.Set("cookie", client.ses.String())
	}
	response, err := client.http.Do(request)
	if err != nil {
		return nil, err
	}

	defer response.Body.Close()
	resBytes, err = ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	if opts.Opts.DebugCmonRpc {
		zap.L().Sugar().Debugf("Reply from cmon %s:\n%s",
			uri, string(resBytes))
	}

	// whenever we do an authentication lets save/update the cmon's version as well
	if request.URL != nil && strings.Contains(request.URL.Path, "auth") {
		// obtain the server version number
		if server := strings.Split(response.Header.Get("Server"), "/"); len(server) > 1 {
			// Server: cmon/1.8.2 -> 1.8.2
			client.serverVersion = strings.Trim(server[1], "\r\n\t '\"")
		}
	}

	client.saveSessionFromResponse(response)

	if autoAuth && (response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden) {
		if err := client.Authenticate(); err != nil {
			return nil, err
		}
		// after auth, we must go with no auto auth
		return client.RequestBytes(module, reqBytes, true)
	}

	return resBytes, nil
}

// Request does an RPCv2 request to cmon. It authenticates and re-authenticates automatically.
func (client *Client) Request(module string, req, res interface{}, noAutoAuth ...bool) error {
	reqBytes, err := json.Marshal(req)
	if err != nil {
		return err
	}
	respBytes, err := client.RequestBytes(module, reqBytes, noAutoAuth...)
	if err != nil {
		return err
	}

	// this part might be not efficient, lets think about this later
	switch req.(type) {
	case *api.AuthenticateRequest:
		// obtain controller ID
		var ctrlID api.WithControllerID
		json.Unmarshal(respBytes, &ctrlID)
		client.controllerID = ctrlID.ControllerID
	}
	var respData api.WithResponseData
	json.Unmarshal(respBytes, &respData)
	client.lastRequestStatus = respData.RequestStatus

	return json.Unmarshal(respBytes, res)
}

// Authenticate does RPCv2 authentication.
func (client *Client) Authenticate() error {
	if len(client.Instance.Password) > 0 {
		return client.AuthenticateWithPassword()
	}

	if len(client.Instance.Keyfile) > 0 {
		return client.AuthenticateWithKey()
	}

	client.lastRequestStatus = api.RequestStatusAuthRequired
	return fmt.Errorf("no password or keyfile is defined")
}

func (client *Client) AuthenticateWithPassword() error {
	rd := &api.AuthenticateRequest{
		WithOperation: &api.WithOperation{
			Operation: "authenticateWithPassword",
		},
		LdapOnly: client.Instance.UseLdap,
		UserName: client.Instance.Username,
		Password: client.Instance.Password,
	}

	ar := &api.AuthenticateResponse{}
	if err := client.Request(api.ModuleAuth, rd, ar, true); err != nil {
		return err
	}

	if ar.RequestStatus != api.RequestStatusOk {
		return api.NewErrorFromResponseData(ar.WithResponseData)
	}

	client.mtx.Lock()
	client.user = ar.User
	client.mtx.Unlock()

	return nil
}

func loadRsaKey(filename string) (*rsa.PrivateKey, error) {
	var key *rsa.PrivateKey
	if len(filename) < 1 {
		return key, fmt.Errorf("empty key filename")
	}
	contents, err := ioutil.ReadFile(filename)
	if err != nil {
		return key, err
	}
	if block, _ := pem.Decode(contents); block == nil {
		return key, fmt.Errorf("PEM reading (%s) error", filename)
	} else if parsed, _ := x509.ParsePKCS1PrivateKey(block.Bytes); parsed != nil {
		// method one for "RSA PRIVATE KEY" files ^
		key = parsed
	} else if parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
		// 2nd method for more generic "PRIVATE KEY" files ^^
		return key, err
	} else {
		if key = parsed.(*rsa.PrivateKey); key == nil {
			return key, fmt.Errorf("no private key in %s", filename)
		}
	}
	return key, nil
}

func (client *Client) AuthenticateWithKey() error {
	rsaKey, err := loadRsaKey(client.Instance.Keyfile)
	if err != nil {
		client.lastRequestStatus = api.RequestStatusAuthRequired
		return err
	}
	rd := &api.AuthenticateRequest{
		WithOperation: &api.WithOperation{
			Operation: "authenticate",
		},
		UserName: client.Instance.Username,
	}
	ar := &api.AuthenticateResponse{}
	if err := client.Request(api.ModuleAuth, rd, ar, true); err != nil {
		return err
	}

	if ar.RequestStatus != api.RequestStatusOk {
		return api.NewErrorFromResponseData(ar.WithResponseData)
	}

	signature := ""
	hash := sha256.Sum256([]byte(ar.Challenge))
	if signatureBytes, err := rsaKey.Sign(rand.Reader, hash[:], crypto.SHA256); err != nil {
		return err
	} else {
		signature = base64.StdEncoding.EncodeToString(signatureBytes)
	}

	// responding to the challenge request
	cr := &api.Authenticate2Request{
		WithOperation: &api.WithOperation{
			Operation: "authenticateResponse",
		},
		Signature: signature,
	}
	if err := client.Request(api.ModuleAuth, cr, ar, true); err != nil {
		return err
	}

	if ar.RequestStatus != api.RequestStatusOk {
		return api.NewErrorFromResponseData(ar.WithResponseData)
	}

	client.mtx.Lock()
	client.user = ar.User
	client.mtx.Unlock()
	return nil
}

func (client *Client) buildURI(module string) string {
	urlStr := client.Instance.Url
	if !strings.HasPrefix(urlStr, "https://") {
		urlStr = "https://" + urlStr
	}
	if parsed, err := url.Parse(urlStr); err != nil {
		zap.L().Sugar().Fatalf("URL parse '%s' failure: %s", urlStr, err.Error())
		return ""
	} else {
		u := &url.URL{
			Host:   parsed.Host,
			Scheme: parsed.Scheme,
			Path:   "/v2/" + module,
		}
		// it might already have the full URL
		if strings.HasSuffix(module, "/v2") {
			u.Path = module
		}
		return u.String()
	}
}

func (client *Client) saveSessionFromResponse(res *http.Response) bool {
	for _, c := range res.Cookies() {
		if c.Name == "cmon-sid" {
			client.mtx.Lock()
			client.ses = c
			client.mtx.Unlock()
			return true
		}
	}
	return false
}

func (client *Client) User() *api.User {
	client.mtx.Lock()
	defer client.mtx.Unlock()
	return client.user
}

func (client *Client) ControllerID() string {
	return client.controllerID
}

func (client *Client) RequestStatus() string {
	return client.lastRequestStatus
}

func (client *Client) ServerVersion() string {
	return client.serverVersion
}
