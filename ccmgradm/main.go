package main

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
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	arg "github.com/alexflint/go-arg"
	"github.com/go-ini/ini"
	"github.com/rs/xid"
	"github.com/severalnines/cmon-proxy/config"
	"github.com/severalnines/cmon-proxy/opts"
)

var (
	httpCli *http.Client

	configFile = "ccmgr.yaml"
	address    = "https://127.0.0.1:19051/proxy/admin/reload"
)

type DropUserCmd struct {
	Username string `arg:"positional"`
}

type AddUpdateUserCmd struct {
	Username     string `arg:"positional"`
	Password     string `arg:"positional"`
	EmailAddress string `arg:"-e,--email"`
}

type AddControllerCmd struct {
	Url         string `arg:"positional" help:"The controller's RPC(v2) URL"`
	UseLdap     bool   `arg:"-l,--use-ldap" help:"Use LDAP login to controller"`
	Username    string `arg:"-u,--username" help:"Static non-LDAP credentials"`
	Password    string `arg:"-p,--password" help:"Static non-LDAP credentials"`
	Name        string `arg:"-n,--name" help:"Controller name (default: hostname from URL)"`
	FrontendUrl string `arg:"-f,--frontend-url" help:"The ClusterControl WEB UI URL of this controller"`
}

type InitCmd struct {
	LocalCmon    bool   `arg:"--local-cmon" help:"Initialize with local cmon installation"`
	Port         int    `arg:"-p,--port" help:"Port to start the daemon on (default: 19051)"`
	FrontendPath string `arg:"-f,--frontend-path" help:"Path to web ui static files"`
	Config       string `arg:"-c,--cmon-config" help:"Cmon config (default: /etc/cmon.cnf)"`
	Url          string `arg:"-u,--cmon-url" help:"Cmon url (default: 127.0.0.1:9501)"`
	CMONSshUrl   string `arg:"-s,--cmon-ssh-url" help:"cmon-ssh url (default: 127.0.0.1:9511)"`
	EnableMcc    bool   `arg:"-s,--enable-mcc" help:"Enable multicontroller mode"`
}

type DropControllerCmd struct {
	UrlOrName string `arg:"positional" help:"The controller name or URL from configuration."`
}

type ListControllersCmd struct {
}

type EnableMcc struct {
	Enable bool `arg:"-e,--enable" help:"Enable MCC"`
}

var args struct {
	DropUser         *DropUserCmd        `arg:"subcommand:dropuser"`
	AddUser          *AddUpdateUserCmd   `arg:"subcommand:adduser"`
	SetPassword      *AddUpdateUserCmd   `arg:"subcommand:setpassword"`
	DropController   *DropControllerCmd  `arg:"subcommand:dropcontroller"`
	AddController    *AddControllerCmd   `arg:"subcommand:addcontroller"`
	Init             *InitCmd            `arg:"subcommand:init"`
	UpdateController *AddControllerCmd   `arg:"subcommand:updatecontroller"`
	ListControllers  *ListControllersCmd `arg:"subcommand:listcontrollers"`
	EnableMcc  		 *EnableMcc 		 `arg:"subcommand:enableMcc"`
}

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
	fmt.Println("ClusterControl Manager - admin CLI v2.2")

	arg.MustParse(&args)

	// most options require a config update as well
	saveAndReload := true

	// Load configuration
	cfg, err := config.Load(path.Join(opts.Opts.BaseDir, configFile), true)
	if err != nil {
		// 2nd chance for docker
		cfg, err = config.Load(path.Join("/data", configFile), true)
	}
	if err != nil {
		// 3nd chance for dev
		cfg, err = config.Load(path.Join("", configFile), true)
	}
	if err != nil {
		fmt.Println("Config file load error:", err.Error())
		os.Exit(1)
	}

	switch {
	case args.AddUser != nil:
		{
			proxyUser, _ := cfg.GetUser(args.AddUser.Username)
			if proxyUser != nil {
				fmt.Println("User already exists.")
				os.Exit(1)
			}
			proxyUser = &config.ProxyUser{
				Username:     args.AddUser.Username,
				EmailAddress: args.AddUser.EmailAddress,
			}
			if len(args.AddUser.Password) < 1 {
				fmt.Println("A non-empty password is required.")
				os.Exit(1)
			}
			proxyUser.SetPassword(args.AddUser.Password)
			if err := cfg.AddUser(proxyUser); err != nil {
				fmt.Println("User add failed:", err.Error())
				os.Exit(1)
			}
		}
	case args.SetPassword != nil:
		{
			proxyUser, _ := cfg.GetUser(args.SetPassword.Username)
			if proxyUser == nil {
				fmt.Println("User not found.")
				os.Exit(1)
			}
			// optionally update the e-mail address as well
			if len(args.SetPassword.EmailAddress) > 3 {
				proxyUser.EmailAddress = args.SetPassword.EmailAddress
			}
			if len(args.SetPassword.Password) < 1 {
				fmt.Println("A non-empty password is required.")
				os.Exit(1)
			}
			proxyUser.SetPassword(args.SetPassword.Password)
			if err := cfg.UpdateUser(proxyUser); err != nil {
				fmt.Println("User update failed:", err.Error())
				os.Exit(1)
			}
		}
	case args.DropUser != nil:
		{
			if err := cfg.RemoveUser(args.DropUser.Username); err != nil {
				fmt.Println("Removing user has failed:", err.Error())
				os.Exit(1)
			}

		}
	case args.DropController != nil:
		{
			if len(args.DropController.UrlOrName) < 1 {
				fmt.Println("URL or name can not be empty.")
				os.Exit(1)
			}
			cmon := cfg.ControllerById(args.DropController.UrlOrName)
			if cmon == nil {
				fmt.Println("Controller not found")
				os.Exit(0) // ? maybe error ?
			}

			if err := cfg.RemoveController(cmon.Url, false); err != nil {
				fmt.Println("Couldn't remove controller:", err.Error())
				os.Exit(1)
			}
		}
	case args.AddController != nil:
		{
			if len(args.AddController.Url) < 3 {
				fmt.Println("Error, controller URL can not be empty.")
				os.Exit(1)
			}
			cmon := cfg.ControllerByUrl(args.AddController.Url)
			if cmon != nil {
				fmt.Println("Controller already exists with this URL.")
				os.Exit(1)
			}
			cmon = &config.CmonInstance{
				Xid:         xid.New().String(),
				Url:         args.AddController.Url,
				Name:        args.AddController.Name,
				UseLdap:     args.AddController.UseLdap,
				FrontendUrl: args.AddController.FrontendUrl,
			}
			if len(cmon.Name) < 1 {
				if u, err := url.Parse(cmon.Url); err == nil {
					cmon.Name = u.Hostname()
				}
			}
			// save static credentials only for non-LDAP controllers
			if !cmon.UseLdap {
				cmon.Username = args.AddController.Username
				cmon.Password = args.AddController.Password
			}
			if err := cfg.AddController(cmon, false); err != nil {
				fmt.Println("Couldn't add controller:", err.Error())
				os.Exit(1)
			}
		}
	case args.Init != nil:
		{
			saveAndReload = false
			if args.Init.LocalCmon {
				cmonUrl := "127.0.0.1:9501"
				if len(args.Init.Url) > 0 {
					cmonUrl = args.Init.Url
				}
				cmonSshUrl := "127.0.0.1:9511"
				if len(args.Init.CMONSshUrl) > 0 {
					cmonSshUrl = args.Init.CMONSshUrl
				}
				cmon := cfg.ControllerByUrl(cmonUrl)
				if cmon != nil {
					fmt.Println("Controller already exists with this URL.")
					os.Exit(1)
				}
				cmon = &config.CmonInstance{
					Xid:         xid.New().String(),
					Url:         cmonUrl,
					CMONSshHost: cmonSshUrl,
					Name:        "local",
					UseCmonAuth: true,
					FrontendUrl: "localhost",
				}

				if (!args.Init.EnableMcc) {
					cfg.SingleController = cmon.Xid
				} 

				// configFile := "/etc/cmon.cnf"
				var cmonConfig string
				var cfgFile *ini.File
				if len(args.Init.Config) > 0 {
					cmonConfig = args.Init.Config
				}
				if cmonConfig != "" {
					cfgFile, err = ini.Load(configFile)
					if err != nil {
						fmt.Println("Error loading cmon.cnf file:", err.Error())
						os.Exit(1)
					}
					rpcKey := cfgFile.Section("").Key("rpc_key").String()
					if rpcKey == "" {
						fmt.Println("Error, rpc_key not found in .cnf file.")
						os.Exit(1)
					}
					cmon.Username = "ccrpc"
					cmon.Password = rpcKey
				}

				if err := cfg.AddController(cmon, false); err != nil {
					fmt.Println("Couldn't add controller:", err.Error())
					os.Exit(1)
				}

				fmt.Println("Controller", cmonUrl, "registered successfully")

			}
			if args.Init.Port > 0 && cfg.Port != args.Init.Port {
				fmt.Println("Changing port from", cfg.Port, "to", args.Init.Port)
				cfg.Port = args.Init.Port
			}
			if len(args.Init.FrontendPath) > 0 && cfg.FrontendPath != args.Init.FrontendPath {
				fmt.Println("Changing frontend_path from", cfg.FrontendPath, "to", args.Init.FrontendPath)
				cfg.FrontendPath = args.Init.FrontendPath

				// @todo get rid of config.js file and generate env variables for UI dynamically
				filePath := fmt.Sprintf("%s/config.js", cfg.FrontendPath)
				input, err := os.ReadFile(filePath)
				if err != nil {
					fmt.Println(err)
				}
				fileInfo, err := os.Stat(filePath)
				if err != nil {
					fmt.Println(err)
				}
				if input != nil && fileInfo != nil {
					content := string(input)
					updatedContent := strings.Replace(content, "CMON_API_URL: '/api/v2'", "CMON_API_URL: '/'", 1)
					err = os.WriteFile(filePath, []byte(updatedContent), fileInfo.Mode().Perm())
					if err != nil {
						fmt.Println(err)
					} else {
						fmt.Println("File", filePath, "updated successfully")
					}
				}
			}
			if err := cfg.Save(); err != nil {
				fmt.Println("Couldn't update configuration:", err.Error())
				os.Exit(1)
			} else {
				fmt.Println("Configuration", cfg.Filename, "updated successfully")
			}
			fmt.Println("Please restart 'cmon-proxy' service to apply changes")
		}
	case args.UpdateController != nil:
		{
			cmon := cfg.ControllerByUrl(args.UpdateController.Url)
			if cmon == nil {
				fmt.Println("Couldn't find controller.")
				os.Exit(1)
			}
			// make sure all instances have a valid internal ID
			if len(cmon.Xid) < 4 {
				cmon.Xid = xid.New().String()
			}
			// Name
			if len(args.UpdateController.Name) > 0 {
				cmon.Name = args.UpdateController.Name
			} else if len(cmon.Name) < 1 {
				if u, err := url.Parse(cmon.Url); err == nil {
					cmon.Name = u.Hostname()
				}
			}
			cmon.UseLdap = args.UpdateController.UseLdap
			if args.UpdateController.UseLdap {
				cmon.Username = ""
				cmon.Password = ""
			} else {
				if len(args.UpdateController.Username) > 0 {
					cmon.Username = args.UpdateController.Username
				}
				if len(args.UpdateController.Password) > 0 {
					cmon.Password = args.UpdateController.Password
				}
				if len(cmon.Username) < 1 || len(cmon.Password) < 1 {
					fmt.Println("Controller credentials can not be empty (for non LDAP logins).")
					os.Exit(1)
				}
			}
			if len(args.UpdateController.FrontendUrl) > 0 {
				cmon.FrontendUrl = args.UpdateController.FrontendUrl
			}
		}
	case args.ListControllers != nil:
		{
			// not need to save
			saveAndReload = false
			fmt.Println()
			fmt.Println("Controllers from configuration:")
			for _, url := range cfg.ControllerUrls() {
				cmon := cfg.ControllerByUrl(url)
				fmt.Print("* ", cmon.Url)
				if len(cmon.Name) > 0 {
					fmt.Print(" [", cmon.Name, "]")
				}
				if cmon.UseLdap {
					fmt.Print(" *LDAP authentication*")
				} else {
					fmt.Print(" Static user: ", cmon.Username)
				}
				if len(cmon.FrontendUrl) > 0 {
					fmt.Print(" Web-UI:", cmon.FrontendUrl)
				}
				fmt.Println()
			}
		}
	case args.EnableMcc != nil:
		{
			if (args.EnableMcc.Enable) {
				fmt.Println("Enabling MCC")
				cfg.SingleController = ""
			} 
		}
	default:
		fmt.Println("Unknown subcommand, please see", os.Args[0], "--help for documentation.")
	}

	// exit when no need to save
	if !saveAndReload {
		return
	}

	if err := cfg.Save(); err != nil {
		fmt.Println("Couldn't update configuration:", err.Error())
		os.Exit(1)
	}

	if cfg.Port > 0 {
		address = fmt.Sprintf("https://127.0.0.1:%d/proxy/admin/reload", cfg.Port)
	}

	if err := reloadDaemon(); err != nil {
		fmt.Println("Please restart 'cmon-proxy' service to apply changes.")
	} else {
		fmt.Println("Config reloaded successfully")
	}
}
