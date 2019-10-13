package core

import (
	"github.com/miekg/dns"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/kgretzky/evilginx2/log"
)

type Nameserver struct {
	srv    *dns.Server
	cfg    *Config
	serial uint32
	txt    map[string]TXTField
}

type TXTField struct {
	fqdn  string
	value string
	ttl   int
}

func NewNameserver(cfg *Config) (*Nameserver, error) {
	n := &Nameserver{
		serial: uint32(time.Now().Unix()),
		cfg:    cfg,
	}
	n.txt = make(map[string]TXTField)

	n.Reset()

	return n, nil
}

func (n *Nameserver) Reset() {
	dns.HandleFunc(pdom(n.cfg.baseDomain), n.handleRequest)
}

func (n *Nameserver) Start() {
	go func() {
		n.srv = &dns.Server{Addr: ":53", Net: "udp"}
		if err := n.srv.ListenAndServe(); err != nil {
			log.Fatal("Failed to start nameserver on port 53")
		}
	}()
}

func (n *Nameserver) AddTXT(fqdn string, value string, ttl int) {
	txt := TXTField{
		fqdn:  fqdn,
		value: value,
		ttl:   ttl,
	}
	n.txt[fqdn] = txt
}

func (n *Nameserver) ClearTXT() {
	n.txt = make(map[string]TXTField)
}

func (n *Nameserver) handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)

	if n.cfg.baseDomain == "" || n.cfg.serverIP == "" {
		return
	}

	soa := &dns.SOA{
		Hdr:     dns.RR_Header{Name: pdom(n.cfg.baseDomain), Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
		Ns:      "ns1." + pdom(n.cfg.baseDomain),
		Mbox:    "hostmaster." + pdom(n.cfg.baseDomain),
		Serial:  n.serial,
		Refresh: 900,
		Retry:   900,
		Expire:  1800,
		Minttl:  60,
	}
	m.Ns = []dns.RR{soa}

	switch r.Question[0].Qtype {
	case dns.TypeA:
		log.Debug("DNS A: " + strings.ToLower(r.Question[0].Name) + " = " + n.cfg.serverIP)
		rr := &dns.A{
			Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP(n.cfg.serverIP),
		}
		m.Answer = append(m.Answer, rr)
	case dns.TypeNS:
		log.Debug("DNS NS: " + strings.ToLower(r.Question[0].Name))
		if strings.ToLower(r.Question[0].Name) == pdom(n.cfg.baseDomain) {
			for _, i := range []int{1, 2} {
				rr := &dns.NS{
					Hdr: dns.RR_Header{Name: pdom(n.cfg.baseDomain), Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
					Ns:  "ns" + strconv.Itoa(i) + "." + pdom(n.cfg.baseDomain),
				}
				m.Answer = append(m.Answer, rr)
			}
		}
	case dns.TypeTXT:
		log.Debug("DNS TXT: " + strings.ToLower(r.Question[0].Name))
		txt, ok := n.txt[strings.ToLower(m.Question[0].Name)]

		if ok {
			rr := &dns.TXT{
				Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: uint32(txt.ttl)},
				Txt: []string{txt.value},
			}
			m.Answer = append(m.Answer, rr)
		}
	}
	w.WriteMsg(m)
}

func pdom(domain string) string {
	return domain + "."
}
