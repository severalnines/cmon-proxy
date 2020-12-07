package proxy

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
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/severalnines/ccx/go/cmon"
	"github.com/severalnines/cmon-proxy/config"
	"go.uber.org/zap"
)

// Client struct.
type Client struct {
	Instance *config.CmonInstance
	http     *http.Client
	ses      *http.Cookie
	sesMu    *sync.Mutex
	user     *cmon.User
	userMu   *sync.Mutex
}

// NewClient returns a new RPCv2 client.
func NewClient(instance *config.CmonInstance, timeout int) *Client {
	httpClient := &http.Client{
		Timeout: time.Second * time.Duration(timeout),
	}
	httpClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	c := &Client{
		Instance: instance,
		http:     httpClient,
		sesMu:    &sync.Mutex{},
		userMu:   &sync.Mutex{},
	}
	return c
}

// Request does an RPCv2 request to cmon. It authenticates and re-authenticates automatically.
func (client *Client) Request(module string, req, res interface{}, retry bool, authrequest ...bool) error {
	// for regular requests we may want to auto reauthenticate
	autoAuth := len(authrequest) < 1 || !authrequest[0]

	if autoAuth && client.ses == nil {
		if err := client.Authenticate(); err != nil {
			return err
		}
	}
	uri := client.buildURI(module)
	reqBytes, err := json.Marshal(req)
	if err != nil {
		return err
	}
	request, err := http.NewRequest(
		http.MethodPost,
		uri,
		bytes.NewBuffer(reqBytes))
	if err != nil {
		return err
	}
	if client.ses != nil {
		request.Header.Set("cookie", client.ses.String())
	}
	response, err := client.http.Do(request)
	if err != nil {
		return err
	}

	client.saveSessionFromResponse(response)

	// FIXME: this isn't completely right (but doesn't harm), the user may have no access for certain things
	if autoAuth && (response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden) {
		if retry {
			return fmt.Errorf("retry failed after re-authentication")
		}
		if err := client.Authenticate(); err != nil {
			return err
		}
		return client.Request(module, req, res, true)
	}
	rb, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %+v", err)
	}
	return json.Unmarshal(rb, res)
}

// Authenticate does RPCv2 authentication.
func (client *Client) Authenticate() error {
	if len(client.Instance.Password) > 0 {
		return client.AuthenticateWithPassword()
	}

	if len(client.Instance.Keyfile) > 0 {
		return client.AuthenticateWithKey()
	}

	return fmt.Errorf("no password or keyfile is defined")
}

func (client *Client) AuthenticateWithPassword() error {
	rd := &AuthenticateRequest{
		Operation: "authenticateWithPassword",
		UserName:  client.Instance.Username,
		Password:  client.Instance.Password,
	}

	ar := &AuthenticateResponse{}
	if err := client.Request(cmon.ModuleAuth, rd, ar, false, true); err != nil {
		return err
	}

	if ar.RequestStatus != cmon.RequestStatusOk {
		return cmon.NewErrorFromResponseData(ar.WithResponseData)
	}

	client.userMu.Lock()
	client.user = ar.User
	client.userMu.Unlock()
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
		return err
	}
	rd := &AuthenticateRequest{
		Operation: "authenticate",
		UserName:  client.Instance.Username,
	}
	ar := &AuthenticateResponse{}
	if err := client.Request(cmon.ModuleAuth, rd, ar, false, true); err != nil {
		return err
	}

	if ar.RequestStatus != cmon.RequestStatusOk {
		return cmon.NewErrorFromResponseData(ar.WithResponseData)
	}

	signature := ""
	hash := sha256.Sum256([]byte(ar.Challenge))
	if signatureBytes, err := rsaKey.Sign(rand.Reader, hash[:], crypto.SHA256); err != nil {
		return err
	} else {
		signature = base64.StdEncoding.EncodeToString(signatureBytes)
	}

	// responding to the challenge request
	cr := &Authenticate2Request{
		Operation: "authenticateResponse",
		Signature: signature,
	}
	if err := client.Request(cmon.ModuleAuth, cr, ar, false, true); err != nil {
		return err
	}

	if ar.RequestStatus != cmon.RequestStatusOk {
		return cmon.NewErrorFromResponseData(ar.WithResponseData)
	}

	client.userMu.Lock()
	client.user = ar.User
	client.userMu.Unlock()
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
		return u.String()
	}
}

func (client *Client) saveSessionFromResponse(res *http.Response) bool {
	for _, c := range res.Cookies() {
		if c.Name == "cmon-sid" {
			client.sesMu.Lock()
			client.ses = c
			client.sesMu.Unlock()
			return true
		}
	}
	return false
}

func (client *Client) User() *cmon.User {
	client.userMu.Lock()
	defer client.userMu.Unlock()
	return client.User()
}
