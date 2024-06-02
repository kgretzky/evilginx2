package core

import (
	"context"
	"fmt"
	"net"
	"os" //added for reading yaml
	"strconv"
	"strings"
	"time"

	"github.com/kgretzky/evilginx2/log"
	"github.com/miekg/dns"
	"gopkg.in/yaml.v2" //added for yaml.
)

// DNSConfig holds configuration for DNS records
type DNSConfig struct {
	TXTRecords   map[string][]Record   `yaml:"txt_records"`
	CNAMERecords map[string]string     `yaml:"cname_records"`
	MXRecords    map[string][]MXRecord `yaml:"mx_records"`
	AAAARecords  map[string][]Record   `yaml:"aaaa_records"`
	PTRRecords   map[string][]Record   `yaml:"ptr_records"` //not implemented yet.
	ARecords     map[string][]Record   `yaml:"a_records"`
}

// Record holds DNS record data
type Record struct {
	TTL   int    `yaml:"ttl"` // Ensure tags match YAML keys
	Value string `yaml:"value"`
}

type MXRecord struct {
	Preference uint16 `yaml:"preference"`
	TTL        int    `yaml:"ttl"`
	Value      string `yaml:"value"`
}

type Nameserver struct {
	srv    *dns.Server
	cfg    *Config
	bind   string
	serial uint32
	ctx    context.Context
	Config DNSConfig
}

func (o *Nameserver) LoadDNSRecords() {
	data, err := os.ReadFile("dns_records.yaml")
	if err != nil {
		log.Debug("Failed to read dns_records.yaml: ", err)
		return
	}

	var config DNSConfig
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		log.Debug("Failed to unmarshal yaml: ", err)
		return
	}
	o.Config = config

	// Log to check contents of the loaded maps
	log.Debug(fmt.Sprintf("TXT Records loaded: %+v", o.Config.TXTRecords))
	log.Debug(fmt.Sprintf("CNAME Records loaded: %+v", o.Config.CNAMERecords))
	log.Debug(fmt.Sprintf("MX Records loaded: %+v", o.Config.MXRecords))
	log.Debug(fmt.Sprintf("AAAA Records loaded: %+v", o.Config.AAAARecords)) // Log AAAA records from yaml
	log.Debug(fmt.Sprintf("PTR Records loaded: %+v", o.Config.PTRRecords))   // Log PTR records from yaml
	log.Debug(fmt.Sprintf("A Records loaded: %+v", o.Config.ARecords))       // Log AAAA records from yaml
}

func NewNameserver(cfg *Config) (*Nameserver, error) {
	o := &Nameserver{
		serial: uint32(time.Now().Unix()),
		cfg:    cfg,
		bind:   fmt.Sprintf("%s:%d", cfg.GetServerBindIP(), cfg.GetDnsPort()),
		ctx:    context.Background(),
	}
	o.LoadDNSRecords()
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

// splitDKIM splits a long DKIM string into parts no longer than maxLen.
func splitDKIM(dkim string, maxLen int) []string {
	var parts []string
	for len(dkim) > 0 {
		if len(dkim) > maxLen {
			parts = append(parts, dkim[:maxLen])
			dkim = dkim[maxLen:]
		} else {
			parts = append(parts, dkim)
			break
		}
	}
	return parts
}

func cleanRecordData(data string) string {
	// Trim specific unwanted control characters like \010
	return strings.TrimRight(data, "\n") // Removes newline characters from the end of the string
}

func (o *Nameserver) handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	log.Debug("Starting to handle request")

	if len(r.Question) == 0 {
		log.Debug("No questions in the request")
		return
	}

	m := new(dns.Msg)
	m.SetReply(r)

	edns0 := r.IsEdns0() // Check if the query has EDNS0 extension
	//log.Debug(fmt.Sprintf("edns0: %+v", edns0))
	if edns0 != nil {
		m.SetEdns0(4096, true) // Set the response to use a 4096 byte UDP payload and enable DNSSEC OK
	}

	soa := &dns.SOA{
		Hdr:     dns.RR_Header{Name: pdom(o.cfg.general.Domain), Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 1},
		Ns:      "ns1." + pdom(o.cfg.general.Domain),
		Mbox:    "hostmaster." + pdom(o.cfg.general.Domain),
		Serial:  o.serial,
		Refresh: 900,
		Retry:   900,
		Expire:  1800,
		Minttl:  60,
	}
	m.Ns = []dns.RR{soa}
	//log.Debug(fmt.Sprintf("m.Ns: %+v", m.Ns))

	fqdn := strings.ToLower(r.Question[0].Name)
	normalizedFqdn := strings.TrimSuffix(fqdn, ".") + "." //this trailing . is critical! Keep this consistent as all DNS queries end the urls with . to represent FQDNs.
	queryType := dns.TypeToString[r.Question[0].Qtype]
	log.Debug(fmt.Sprintf("Received query for: %s, type: %s", normalizedFqdn, queryType))

	switch r.Question[0].Qtype {
	case dns.TypeTXT:
		log.Debug("DNS TXT: " + normalizedFqdn)
		if records, ok := o.Config.TXTRecords[normalizedFqdn]; ok {
			for _, record := range records {
				// First, clean the entire record value to remove unwanted characters
				cleanedValue := cleanRecordData(record.Value)
				txtParts := splitDKIM(cleanedValue, 255) // Use the split function to handle long DKIM strings

				txtRecord := &dns.TXT{
					Hdr: dns.RR_Header{
						Name:   normalizedFqdn,
						Rrtype: dns.TypeTXT,
						Class:  dns.ClassINET,
						Ttl:    uint32(record.TTL),
					},
					Txt: txtParts,
				}
				// Log the content of the TXT record being appended
				log.Debug(fmt.Sprintf("Appending TXT record for %s: TTL=%d, Value=%s", normalizedFqdn, record.TTL, record.Value))
				m.Answer = append(m.Answer, txtRecord)
			}
		} else {
			log.Debug("No TXT records found for: " + normalizedFqdn)
		}
	case dns.TypeCNAME:
		log.Debug("DNS CNAME: " + normalizedFqdn)
		if target, ok := o.Config.CNAMERecords[normalizedFqdn]; ok {
			cname := &dns.CNAME{
				Hdr:    dns.RR_Header{Name: normalizedFqdn, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
				Target: target,
			}
			log.Debug(fmt.Sprintf("Appending CNAME record: Target=%s", target))
			m.Answer = append(m.Answer, cname)
		} else {
			log.Debug("No CNAME records found for: " + normalizedFqdn)
		}
	case dns.TypeMX:
		log.Debug("DNS MX: " + normalizedFqdn)
		if mxRecords, ok := o.Config.MXRecords[normalizedFqdn]; ok {
			for _, mxRecord := range mxRecords {
				mx := &dns.MX{
					Hdr: dns.RR_Header{
						Name:   normalizedFqdn,
						Rrtype: dns.TypeMX,
						Class:  dns.ClassINET,
						Ttl:    uint32(mxRecord.TTL), // Use TTL from the YAML configuration
					},
					Preference: mxRecord.Preference,
					Mx:         mxRecord.Value,
				}
				log.Debug(fmt.Sprintf("Appending MX record: Preference=%d, Mx=%s, TTL=%d", mxRecord.Preference, mxRecord.Value, mxRecord.TTL))
				m.Answer = append(m.Answer, mx)
			}
		} else {
			log.Debug("No MX records found for: " + normalizedFqdn)
		}
	case dns.TypeSOA:
		log.Debug("DNS SOA: " + normalizedFqdn)
		log.Debug(fmt.Sprintf("Appending SOA record: NS=%s, Mbox=%s", soa.Ns, soa.Mbox))
		m.Answer = append(m.Answer, soa)
	case dns.TypeNS:
		log.Debug("DNS NS: " + normalizedFqdn)
		if normalizedFqdn == pdom(o.cfg.general.Domain) {
			for _, i := range []int{1, 2} {
				rr := &dns.NS{
					Hdr: dns.RR_Header{Name: pdom(o.cfg.general.Domain), Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
					Ns:  "ns" + strconv.Itoa(i) + "." + pdom(o.cfg.general.Domain),
				}
				log.Debug(fmt.Sprintf("Appending NS record: %s", rr.Ns))
				m.Answer = append(m.Answer, rr)
			}
		}
	case dns.TypeAAAA:
		log.Debug("DNS AAAA: " + normalizedFqdn)
		found := false

		// Search for direct match or any parent domain match
		for domain, records := range o.Config.AAAARecords {
			if normalizedFqdn == domain || strings.HasSuffix(normalizedFqdn, "."+domain) {
				for _, record := range records {
					ipv6Addr := net.ParseIP(record.Value)
					if ipv6Addr == nil { // validate the IPv6 address
						log.Debug("Invalid IPv6 address found: " + record.Value)
						continue
					}
					aaaa := &dns.AAAA{
						Hdr: dns.RR_Header{
							Name:   normalizedFqdn,
							Rrtype: dns.TypeAAAA,
							Class:  dns.ClassINET,
							Ttl:    uint32(record.TTL),
						},
						AAAA: ipv6Addr,
					}
					log.Debug(fmt.Sprintf("Appending AAAA record for %s: TTL=%d, Value=%s", normalizedFqdn, record.TTL, record.Value))
					m.Answer = append(m.Answer, aaaa)
				}
				found = true
				break // Stop searching after finding a match
			}
		}

		if !found {
			log.Debug("No AAAA records found for: " + normalizedFqdn)
		}

	case dns.TypeA:
		log.Debug("DNS A: " + normalizedFqdn)
		found := false

		// Search for direct match or any parent domain match
		for domain, records := range o.Config.ARecords {
			if normalizedFqdn == domain || strings.HasSuffix(normalizedFqdn, "."+domain) {
				for _, record := range records {
					aRecord := &dns.A{
						Hdr: dns.RR_Header{
							Name:   normalizedFqdn,
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    uint32(record.TTL),
						},
						A: net.ParseIP(record.Value),
					}
					log.Debug(fmt.Sprintf("Appending A record for %s: TTL=%d, Value=%s", normalizedFqdn, record.TTL, record.Value))
					m.Answer = append(m.Answer, aRecord)
				}
				found = true
				break // Stop searching after finding a match
			}
		}

		if !found {
			log.Debug("No A records found for: " + normalizedFqdn)
		}
	default:
		log.Debug("Unsupported query type")
	}
	w.WriteMsg(m)
	// log.Debug("w: %+v", w)
	// log.Debug("m: %+v", m)
	log.Debug("Finished handling request")

}

func pdom(domain string) string {
	return domain + "."
}
