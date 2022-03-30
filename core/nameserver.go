package core

import (
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/kgretzky/evilginx2/log"
)

type Nameserver struct {
	srv    *dns.Server
	cfg    *Config
	serial uint32
}

func NewNameserver(cfg *Config) (*Nameserver, error) {
	n := &Nameserver{
		serial: uint32(time.Now().Unix()),
		cfg:    cfg,
	}

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
		var rr dns.TXT

		if dns.SplitDomainName(strings.ToLower(m.Question[0].Name))[0] == "_dmarc" {
			// DMARC for _dmarc.**
			rr = dns.TXT{
				Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
				Txt: []string{n.getDMARC()},
			}
		} else if dns.SplitDomainName(strings.ToLower(m.Question[0].Name))[1] == "_domainkey" {
			// DKIM for *._domainkey.**
			rr = dns.TXT{
				Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
				Txt: []string{n.getDKIM()}, // add strings here to add TXT records
			}
		} else {
			// no special TXT rule caught this, so it will answer default TXT
			rr = dns.TXT{
				Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
				Txt: []string{n.getSPF()}, // add strings here to add TXT records
			}
		}
		if len(rr.Txt[0]) > 255 {
			// max length of txt is 255, split TXT records into multiple TXT records
			rr.Txt = stringchunk(rr.Txt[0], 255)
		}
		m.Answer = append(m.Answer, &rr)
	}
	w.WriteMsg(m)
}

func pdom(domain string) string {
	return domain + "."
}

func (n *Nameserver) getSPF() string {
	if n.cfg.dnscfg["spf"] == "" {
		return "v=spf1 a mx ip4:" + n.cfg.serverIP + " -all"
	} else {
		return n.cfg.dnscfg["spf"]
	}
}

func (n *Nameserver) getDMARC() string {
	if n.cfg.dnscfg["dmarc"] == "" {
		return "v=DMARC1; p=none; rua=mailto:postmaster@" + n.cfg.baseDomain
	} else {
		return n.cfg.dnscfg["dmarc"]
	}
}

func (n *Nameserver) getDKIM() string {
	if n.cfg.dnscfg["dkim"] == "" {
		return ""
	} else {
		return n.cfg.dnscfg["dkim"]
	}
}
