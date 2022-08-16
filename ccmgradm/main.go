package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"path"
	"time"

	"github.com/severalnines/cmon-proxy/config"
	"github.com/severalnines/cmon-proxy/opts"
)

var (
	httpCli *http.Client

	configFile = "ccmgr.yaml"
	address    = "https://127.0.0.1:19051/proxy/admin/reload"
)

func init() {
	customTransport := http.DefaultTransport.(*http.Transport).Clone()
	customTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	httpCli = &http.Client{
		Transport: customTransport,
		Timeout:   60 * time.Second,
	}
}

func reloadDaemon() error {
	_, err := httpCli.Get(address)
	return err
}

func main() {
	opts.Init()
	fmt.Println("ClusterControl Manager - admin CLI v1.0 beta")
	command := ""
	if len(os.Args) > 1 {
		command = os.Args[1]
	}
	commands := make(map[string]bool)
	commands["adduser"] = true
	commands["setpassword"] = true
	commands["dropuser"] = false // this one doesn't need password

	if _, found := commands[command]; !found || len(os.Args) < 3 {
		fmt.Println("Usage: ", os.Args[0], "adduser|setpassword|dropuser USERNAME [PASSWORD]")
		os.Exit(1)
	}
	username := os.Args[2]
	password := ""
	if len(os.Args) > 3 {
		password = os.Args[3]
	}

	cfg, err := config.Load(path.Join(opts.Opts.BaseDir, configFile), true)
	if err != nil {
		// 2nd chance for docker
		cfg, err = config.Load(path.Join("/data", configFile), true)
	}
	if err != nil {
		fmt.Println("Config file load error:", err.Error())
		os.Exit(1)
	}

	if commands[command] && len(password) < 1 {
		fmt.Println("Password is required")
		os.Exit(1)
	}

	proxyUser, err := cfg.GetUser(username)

	if command == "adduser" {
		if proxyUser != nil {
			fmt.Println("User already exists.")
			os.Exit(1)
		}
		proxyUser := &config.ProxyUser{Username: username}
		proxyUser.SetPassword(password)
		if err := cfg.AddUser(proxyUser); err != nil {
			fmt.Println("User add failed:", err.Error())
			os.Exit(1)
		}
	} else {
		// we need an existing user for setpassword and dropuser
		if proxyUser == nil {
			err = fmt.Errorf("user not found")
		}
		if err != nil {
			fmt.Println("Failure:", err.Error())
			os.Exit(1)
		}

		if command == "setpassword" {
			proxyUser.SetPassword(password)
			if err := cfg.UpdateUser(proxyUser); err != nil {
				fmt.Println("Setting password has failed:", err.Error())
				os.Exit(1)
			}
		} else if command == "dropuser" {
			if err := cfg.RemoveUser(username); err != nil {
				fmt.Println("Removing user has failed:", err.Error())
				os.Exit(1)
			}
		}
	}

	if err := cfg.Save(); err != nil {
		fmt.Println("Couldn't update configuration:", err.Error())
		os.Exit(1)
	}

	if cfg.Port > 0 {
		address = fmt.Sprintf("https://127.0.0.1:%d/proxy/admin/reload", cfg.Port)
	}

	fmt.Println("Succeed, reloading daemon.")
	if err := reloadDaemon(); err != nil {
		fmt.Println("Warning: failed to reload daemon:", err.Error())
	}
}
