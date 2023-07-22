package core

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kgretzky/evilginx2/log"

	"github.com/spf13/viper"
)

var BLACKLIST_MODES = []string{"all", "unauth", "noadd", "off"}

type Lure struct {
	Hostname        string `mapstructure:"hostname" json:"hostname" yaml:"hostname"`
	Path            string `mapstructure:"path" json:"path" yaml:"path"`
	RedirectUrl     string `mapstructure:"redirect_url" json:"redirect_url" yaml:"redirect_url"`
	Phishlet        string `mapstructure:"phishlet" json:"phishlet" yaml:"phishlet"`
	Redirector      string `mapstructure:"redirector" json:"redirector" yaml:"redirector"`
	UserAgentFilter string `mapstructure:"ua_filter" json:"ua_filter" yaml:"ua_filter"`
	Info            string `mapstructure:"info" json:"info" yaml:"info"`
	OgTitle         string `mapstructure:"og_title" json:"og_title" yaml:"og_title"`
	OgDescription   string `mapstructure:"og_desc" json:"og_desc" yaml:"og_desc"`
	OgImageUrl      string `mapstructure:"og_image" json:"og_image" yaml:"og_image"`
	OgUrl           string `mapstructure:"og_url" json:"og_url" yaml:"og_url"`
}

type SubPhishlet struct {
	Name       string            `mapstructure:"name" json:"name" yaml:"name"`
	ParentName string            `mapstructure:"parent_name" json:"parent_name" yaml:"parent_name"`
	Params     map[string]string `mapstructure:"params" json:"params" yaml:"params"`
}

type PhishletConfig struct {
	Hostname string `mapstructure:"hostname" json:"hostname" yaml:"hostname"`
	Enabled  bool   `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
	Visible  bool   `mapstructure:"visible" json:"visible" yaml:"visible"`
}

type ProxyConfig struct {
	Type     string `mapstructure:"type" json:"type" yaml:"type"`
	Address  string `mapstructure:"address" json:"address" yaml:"address"`
	Port     int    `mapstructure:"port" json:"port" yaml:"port"`
	Username string `mapstructure:"username" json:"username" yaml:"username"`
	Password string `mapstructure:"password" json:"password" yaml:"password"`
	Enabled  bool   `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
}

type BlacklistConfig struct {
	Mode string `mapstructure:"mode" json:"mode" yaml:"mode"`
}

type CertificatesConfig struct {
}

type GeneralConfig struct {
	Domain       string `mapstructure:"domain" json:"domain" yaml:"domain"`
	OldIpv4      string `mapstructure:"ipv4" json:"ipv4" yaml:"ipv4"`
	ExternalIpv4 string `mapstructure:"external_ipv4" json:"external_ipv4" yaml:"external_ipv4"`
	BindIpv4     string `mapstructure:"bind_ipv4" json:"bind_ipv4" yaml:"bind_ipv4"`
	RedirectUrl  string `mapstructure:"redirect_url" json:"redirect_url" yaml:"redirect_url"`
	HttpsPort    int    `mapstructure:"https_port" json:"https_port" yaml:"https_port"`
	DnsPort      int    `mapstructure:"dns_port" json:"dns_port" yaml:"dns_port"`
}

type Config struct {
	general         *GeneralConfig
	certificates    *CertificatesConfig
	blacklistConfig *BlacklistConfig
	proxyConfig     *ProxyConfig
	phishletConfig  map[string]*PhishletConfig
	phishlets       map[string]*Phishlet
	phishletNames   []string
	activeHostnames []string
	redirectorsDir  string
	lures           []*Lure
	subphishlets    []*SubPhishlet
	cfg             *viper.Viper
}

const (
	CFG_GENERAL      = "general"
	CFG_CERTIFICATES = "certificates"
	CFG_LURES        = "lures"
	CFG_PROXY        = "proxy"
	CFG_PHISHLETS    = "phishlets"
	CFG_BLACKLIST    = "blacklist"
	CFG_SUBPHISHLETS = "subphishlets"
)

const DEFAULT_REDIRECT_URL = "https://www.youtube.com/watch?v=dQw4w9WgXcQ" // Rick'roll

func NewConfig(cfg_dir string, path string) (*Config, error) {
	c := &Config{
		general:         &GeneralConfig{},
		certificates:    &CertificatesConfig{},
		phishletConfig:  make(map[string]*PhishletConfig),
		phishlets:       make(map[string]*Phishlet),
		phishletNames:   []string{},
		lures:           []*Lure{},
		blacklistConfig: &BlacklistConfig{},
	}

	c.cfg = viper.New()
	c.cfg.SetConfigType("json")

	if path == "" {
		path = filepath.Join(cfg_dir, "config.json")
	}
	err := os.MkdirAll(filepath.Dir(path), os.FileMode(0700))
	if err != nil {
		return nil, err
	}
	var created_cfg bool = false
	c.cfg.SetConfigFile(path)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		created_cfg = true
		err = c.cfg.WriteConfigAs(path)
		if err != nil {
			return nil, err
		}
	}

	err = c.cfg.ReadInConfig()
	if err != nil {
		return nil, err
	}

	c.cfg.UnmarshalKey(CFG_GENERAL, &c.general)
	c.cfg.UnmarshalKey(CFG_BLACKLIST, &c.blacklistConfig)

	if c.general.OldIpv4 != "" {
		if c.general.ExternalIpv4 == "" {
			c.SetServerExternalIP(c.general.OldIpv4)
		}
		c.SetServerIP("")
	}

	if !stringExists(c.blacklistConfig.Mode, BLACKLIST_MODES) {
		c.SetBlacklistMode("unauth")
	}

	if c.general.RedirectUrl == "" && created_cfg {
		c.SetRedirectUrl(DEFAULT_REDIRECT_URL)
	}
	if c.general.HttpsPort == 0 {
		c.SetHttpsPort(443)
	}
	if c.general.DnsPort == 0 {
		c.SetDnsPort(53)
	}

	c.lures = []*Lure{}
	c.cfg.UnmarshalKey(CFG_LURES, &c.lures)
	c.proxyConfig = &ProxyConfig{}
	c.cfg.UnmarshalKey(CFG_PROXY, &c.proxyConfig)
	c.cfg.UnmarshalKey(CFG_PHISHLETS, &c.phishletConfig)
	c.cfg.UnmarshalKey(CFG_CERTIFICATES, &c.certificates)

	return c, nil
}

func (c *Config) PhishletConfig(site string) *PhishletConfig {
	if o, ok := c.phishletConfig[site]; ok {
		return o
	} else {
		o := &PhishletConfig{
			Hostname: "",
			Enabled:  false,
			Visible:  true,
		}
		c.phishletConfig[site] = o
		return o
	}
}

func (c *Config) SavePhishlets() {
	c.cfg.Set(CFG_PHISHLETS, c.phishletConfig)
	c.cfg.WriteConfig()
}

func (c *Config) SetSiteHostname(site string, hostname string) bool {
	if c.general.Domain == "" {
		log.Error("you need to set server top-level domain, first. type: server your-domain.com")
		return false
	}
	pl, err := c.GetPhishlet(site)
	if err != nil {
		log.Error("%v", err)
		return false
	}
	if pl.isTemplate {
		log.Error("phishlet is a template - can't set hostname")
		return false
	}
	if hostname != "" && hostname != c.general.Domain && !strings.HasSuffix(hostname, "."+c.general.Domain) {
		log.Error("phishlet hostname must end with '%s'", c.general.Domain)
		return false
	}
	log.Info("phishlet '%s' hostname set to: %s", site, hostname)
	c.PhishletConfig(site).Hostname = hostname
	c.SavePhishlets()
	return true
}

func (c *Config) SetBaseDomain(domain string) {
	c.general.Domain = domain
	c.cfg.Set(CFG_GENERAL, c.general)
	log.Info("server domain set to: %s", domain)
	c.cfg.WriteConfig()
}

func (c *Config) SetServerIP(ip_addr string) {
	c.general.OldIpv4 = ip_addr
	c.cfg.Set(CFG_GENERAL, c.general)
	//log.Info("server IP set to: %s", ip_addr)
	c.cfg.WriteConfig()
}

func (c *Config) SetServerExternalIP(ip_addr string) {
	c.general.ExternalIpv4 = ip_addr
	c.cfg.Set(CFG_GENERAL, c.general)
	log.Info("server external IP set to: %s", ip_addr)
	c.cfg.WriteConfig()
}

func (c *Config) SetServerBindIP(ip_addr string) {
	c.general.BindIpv4 = ip_addr
	c.cfg.Set(CFG_GENERAL, c.general)
	log.Info("server bind IP set to: %s", ip_addr)
	log.Warning("you may need to restart evilginx for the changes to take effect")
	c.cfg.WriteConfig()
}

func (c *Config) SetHttpsPort(port int) {
	c.general.HttpsPort = port
	c.cfg.Set(CFG_GENERAL, c.general)
	log.Info("https port set to: %d", port)
	c.cfg.WriteConfig()
}

func (c *Config) SetDnsPort(port int) {
	c.general.DnsPort = port
	c.cfg.Set(CFG_GENERAL, c.general)
	log.Info("dns port set to: %d", port)
	c.cfg.WriteConfig()
}

func (c *Config) EnableProxy(enabled bool) {
	c.proxyConfig.Enabled = enabled
	c.cfg.Set(CFG_PROXY, c.proxyConfig)
	if enabled {
		log.Info("enabled proxy")
	} else {
		log.Info("disabled proxy")
	}
	c.cfg.WriteConfig()
}

func (c *Config) SetProxyType(ptype string) {
	ptypes := []string{"http", "https", "socks5", "socks5h"}
	if !stringExists(ptype, ptypes) {
		log.Error("invalid proxy type selected")
		return
	}
	c.proxyConfig.Type = ptype
	c.cfg.Set(CFG_PROXY, c.proxyConfig)
	log.Info("proxy type set to: %s", ptype)
	c.cfg.WriteConfig()
}

func (c *Config) SetProxyAddress(address string) {
	c.proxyConfig.Address = address
	c.cfg.Set(CFG_PROXY, c.proxyConfig)
	log.Info("proxy address set to: %s", address)
	c.cfg.WriteConfig()
}

func (c *Config) SetProxyPort(port int) {
	c.proxyConfig.Port = port
	c.cfg.Set(CFG_PROXY, c.proxyConfig.Port)
	log.Info("proxy port set to: %d", port)
	c.cfg.WriteConfig()
}

func (c *Config) SetProxyUsername(username string) {
	c.proxyConfig.Username = username
	c.cfg.Set(CFG_PROXY, c.proxyConfig)
	log.Info("proxy username set to: %s", username)
	c.cfg.WriteConfig()
}

func (c *Config) SetProxyPassword(password string) {
	c.proxyConfig.Password = password
	c.cfg.Set(CFG_PROXY, c.proxyConfig)
	log.Info("proxy password set to: %s", password)
	c.cfg.WriteConfig()
}

func (c *Config) IsLureHostnameValid(hostname string) bool {
	for _, l := range c.lures {
		if l.Hostname == hostname {
			if c.PhishletConfig(l.Phishlet).Enabled {
				return true
			}
		}
	}
	return false
}

func (c *Config) SetSiteEnabled(site string) error {
	pl, err := c.GetPhishlet(site)
	if err != nil {
		log.Error("%v", err)
		return err
	}
	if c.PhishletConfig(site).Hostname == "" {
		return fmt.Errorf("enabling phishlet '%s' requires its hostname to be set up", site)
	}
	if pl.isTemplate {
		return fmt.Errorf("phishlet '%s' is a template - you have to 'create' child phishlet from it, with predefined parameters, before you can enable it.", site)
	}
	c.PhishletConfig(site).Enabled = true
	c.refreshActiveHostnames()
	c.VerifyPhishlets()
	log.Info("enabled phishlet '%s'", site)

	c.SavePhishlets()
	return nil
}

func (c *Config) SetSiteDisabled(site string) error {
	if _, err := c.GetPhishlet(site); err != nil {
		log.Error("%v", err)
		return err
	}
	c.PhishletConfig(site).Enabled = false
	c.refreshActiveHostnames()
	log.Info("disabled phishlet '%s'", site)

	c.SavePhishlets()
	return nil
}

func (c *Config) SetSiteHidden(site string, hide bool) error {
	if _, err := c.GetPhishlet(site); err != nil {
		log.Error("%v", err)
		return err
	}
	c.PhishletConfig(site).Visible = !hide
	c.refreshActiveHostnames()

	if hide {
		log.Info("phishlet '%s' is now hidden and all requests to it will be redirected", site)
	} else {
		log.Info("phishlet '%s' is now reachable and visible from the outside", site)
	}
	c.SavePhishlets()
	return nil
}

func (c *Config) SetRedirectorsDir(path string) {
	c.redirectorsDir = path
}

func (c *Config) ResetAllSites() {
	c.phishletConfig = make(map[string]*PhishletConfig)
	c.SavePhishlets()
}

func (c *Config) IsSiteEnabled(site string) bool {
	return c.PhishletConfig(site).Enabled
}

func (c *Config) IsSiteHidden(site string) bool {
	return !c.PhishletConfig(site).Visible
}

func (c *Config) GetEnabledSites() []string {
	var sites []string
	for k, o := range c.phishletConfig {
		if o.Enabled {
			sites = append(sites, k)
		}
	}
	return sites
}

func (c *Config) SetBlacklistMode(mode string) {
	if stringExists(mode, BLACKLIST_MODES) {
		c.blacklistConfig.Mode = mode
		c.cfg.Set(CFG_BLACKLIST, c.blacklistConfig)
		c.cfg.WriteConfig()
	}
	log.Info("blacklist mode set to: %s", mode)
}

func (c *Config) SetRedirectUrl(url string) {
	c.general.RedirectUrl = url
	c.cfg.Set(CFG_GENERAL, c.general)
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
		for _, host := range pl.GetPhishHosts(false) {
			c.activeHostnames = append(c.activeHostnames, strings.ToLower(host))
		}
	}
	for _, l := range c.lures {
		if stringExists(l.Phishlet, sites) {
			if l.Hostname != "" {
				c.activeHostnames = append(c.activeHostnames, strings.ToLower(l.Hostname))
			}
		}
	}
}

func (c *Config) GetActiveHostnames(site string) []string {
	var ret []string
	sites := c.GetEnabledSites()
	for _, _site := range sites {
		if site == "" || _site == site {
			pl, err := c.GetPhishlet(_site)
			if err != nil {
				continue
			}
			for _, host := range pl.GetPhishHosts(false) {
				ret = append(ret, strings.ToLower(host))
			}
		}
	}
	for _, l := range c.lures {
		if site == "" || l.Phishlet == site {
			if l.Hostname != "" {
				hostname := strings.ToLower(l.Hostname)
				ret = append(ret, hostname)
			}
		}
	}
	return ret
}

func (c *Config) IsActiveHostname(host string) bool {
	host = strings.ToLower(host)
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
	c.VerifyPhishlets()
}

func (c *Config) AddSubPhishlet(site string, parent_site string, customParams map[string]string) error {
	pl, err := c.GetPhishlet(parent_site)
	if err != nil {
		return err
	}
	_, err = c.GetPhishlet(site)
	if err == nil {
		return fmt.Errorf("phishlet '%s' already exists", site)
	}
	sub_pl, err := NewPhishlet(site, pl.Path, &customParams, c)
	if err != nil {
		return err
	}
	sub_pl.ParentName = parent_site

	c.phishletNames = append(c.phishletNames, site)
	c.phishlets[site] = sub_pl
	c.VerifyPhishlets()

	return nil
}

func (c *Config) DeleteSubPhishlet(site string) error {
	pl, err := c.GetPhishlet(site)
	if err != nil {
		return err
	}
	if pl.ParentName == "" {
		return fmt.Errorf("phishlet '%s' can't be deleted - you can only delete child phishlets.", site)
	}

	c.phishletNames = removeString(site, c.phishletNames)
	delete(c.phishlets, site)
	delete(c.phishletConfig, site)
	c.SavePhishlets()
	return nil
}

func (c *Config) LoadSubPhishlets() {
	var subphishlets []*SubPhishlet
	c.cfg.UnmarshalKey(CFG_SUBPHISHLETS, &subphishlets)
	for _, spl := range subphishlets {
		err := c.AddSubPhishlet(spl.Name, spl.ParentName, spl.Params)
		if err != nil {
			log.Error("phishlets: %s", err)
		}
	}
}

func (c *Config) SaveSubPhishlets() {
	var subphishlets []*SubPhishlet
	for _, pl := range c.phishlets {
		if pl.ParentName != "" {
			spl := &SubPhishlet{
				Name:       pl.Name,
				ParentName: pl.ParentName,
				Params:     pl.customParams,
			}
			subphishlets = append(subphishlets, spl)
		}
	}

	c.cfg.Set(CFG_SUBPHISHLETS, subphishlets)
	c.cfg.WriteConfig()
}

func (c *Config) VerifyPhishlets() {
	hosts := make(map[string]string)

	for site, pl := range c.phishlets {
		if pl.isTemplate {
			continue
		}
		for _, ph := range pl.proxyHosts {
			if ph.is_landing || ph.handle_session {
				phish_host := combineHost(ph.phish_subdomain, ph.domain)
				orig_host := combineHost(ph.orig_subdomain, ph.domain)
				if c_site, ok := hosts[phish_host]; ok {
					log.Warning("phishlets: hostname '%s' collision between '%s' and '%s' phishlets", phish_host, site, c_site)
				} else if c_site, ok := hosts[orig_host]; ok {
					log.Warning("phishlets: hostname '%s' collision between '%s' and '%s' phishlets", orig_host, site, c_site)
				}
				hosts[phish_host] = site
				hosts[orig_host] = site
			}
		}
	}
}

func (c *Config) CleanUp() {

	for k := range c.phishletConfig {
		_, err := c.GetPhishlet(k)
		if err != nil {
			delete(c.phishletConfig, k)
		}
	}
	c.SavePhishlets()
	/*
		var sites_enabled []string
		var sites_hidden []string
		for k := range c.siteDomains {
			_, err := c.GetPhishlet(k)
			if err != nil {
				delete(c.siteDomains, k)
			} else {
				if c.IsSiteEnabled(k) {
					sites_enabled = append(sites_enabled, k)
				}
				if c.IsSiteHidden(k) {
					sites_hidden = append(sites_hidden, k)
				}
			}
		}
		c.cfg.Set(CFG_SITE_DOMAINS, c.siteDomains)
		c.cfg.Set(CFG_SITES_ENABLED, sites_enabled)
		c.cfg.Set(CFG_SITES_HIDDEN, sites_hidden)
		c.cfg.WriteConfig()*/
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
	if o, ok := c.phishletConfig[site]; ok {
		return o.Hostname, ok
	}
	return "", false
}

func (c *Config) GetBaseDomain() string {
	return c.general.Domain
}

func (c *Config) GetServerExternalIP() string {
	return c.general.ExternalIpv4
}

func (c *Config) GetServerBindIP() string {
	return c.general.BindIpv4
}

func (c *Config) GetHttpsPort() int {
	return c.general.HttpsPort
}

func (c *Config) GetDnsPort() int {
	return c.general.DnsPort
}

func (c *Config) GetRedirectorsDir() string {
	return c.redirectorsDir
}

func (c *Config) GetBlacklistMode() string {
	return c.blacklistConfig.Mode
}
