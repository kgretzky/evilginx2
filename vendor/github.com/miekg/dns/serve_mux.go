package dns

import (
	"errors"
	"strings"
	"sync"

	"github.com/kgretzky/evilginx2/log"

	"os"

	"gopkg.in/yaml.v2"
)

// ServeMux is an DNS request multiplexer. It matches the zone name of
// each incoming request against a list of registered patterns add calls
// the handler for the pattern that most closely matches the zone name.
//
// ServeMux is DNSSEC aware, meaning that queries for the DS record are
// redirected to the parent zone (if that is also registered), otherwise
// the child gets the query.
//
// ServeMux is also safe for concurrent access from multiple goroutines.
//
// The zero ServeMux is empty and ready for use.
type ServeMux struct {
	z map[string]Handler
	m sync.RWMutex
}

// DNSConfig holds configuration for DNS PTR records
type DNSConfig struct {
	PTRRecords map[string][]struct {
		TTL   int    `yaml:"ttl"`
		Value string `yaml:"value"`
	} `yaml:"ptr_records"`
}

// NewServeMux allocates and returns a new ServeMux.
func NewServeMux() *ServeMux {
	return new(ServeMux)
}

// DefaultServeMux is the default ServeMux used by Serve.
var DefaultServeMux = NewServeMux()

func (mux *ServeMux) match(q string, t uint16) Handler {
	mux.m.RLock()
	defer mux.m.RUnlock()
	if mux.z == nil {
		return nil
	}
	q = CanonicalName(q)

	var handler Handler
	for off, end := 0, false; !end; off, end = NextLabel(q, off) {
		if h, ok := mux.z[q[off:]]; ok {
			if t != TypeDS {
				return h
			}
			// Continue for DS to see if we have a parent too, if so delegate to the parent
			handler = h
		}
	}

	// Wildcard match, if we have found nothing try the root zone as a last resort.
	if h, ok := mux.z["."]; ok {
		return h
	}

	return handler
}

// Handle adds a handler to the ServeMux for pattern.
func (mux *ServeMux) Handle(pattern string, handler Handler) {
	if pattern == "" {
		panic("dns: invalid pattern " + pattern)
	}
	mux.m.Lock()
	if mux.z == nil {
		mux.z = make(map[string]Handler)
	}
	mux.z[CanonicalName(pattern)] = handler
	mux.m.Unlock()
}

// HandleFunc adds a handler function to the ServeMux for pattern.
func (mux *ServeMux) HandleFunc(pattern string, handler func(ResponseWriter, *Msg)) {
	mux.Handle(pattern, HandlerFunc(handler))
}

// HandleRemove deregisters the handler specific for pattern from the ServeMux.
func (mux *ServeMux) HandleRemove(pattern string) {
	if pattern == "" {
		panic("dns: invalid pattern " + pattern)
	}
	mux.m.Lock()
	delete(mux.z, CanonicalName(pattern))
	mux.m.Unlock()
}

// ServeDNS dispatches the request to the handler whose pattern most
// closely matches the request message.
//
// ServeDNS is DNSSEC aware, meaning that queries for the DS record
// are redirected to the parent zone (if that is also registered),
// otherwise the child gets the query.
//
// If no handler is found, or there is no question, a standard REFUSED
// message is returned
func (mux *ServeMux) ServeDNS(w ResponseWriter, req *Msg) {
	var h Handler
	var reversedAddr string // Variable to store the reversed IP address
	log.Debug("!ServeDNS")

	//If the query is of type PTR
	if req.Question[0].Qtype == 12 {
		// Check if the domain ends with ".in-addr.arpa." before reversing
		if strings.HasSuffix(req.Question[0].Name, ".in-addr.arpa.") {
			reversedAddr = req.Question[0].Name
			normalAddress, err := NormalizeAddr(req.Question[0].Name)
			if err != nil {
				log.Debug("Error normalizing address:", err)
			} else {
				req.Question[0].Name = normalAddress // Assign the normal address
			}
		}

		//If it already ends with ".", it might need trimming the trailing dot
		if req.Question[0].Name[len(req.Question[0].Name)-1] == '.' {
			req.Question[0].Name = req.Question[0].Name[:len(req.Question[0].Name)-1] // Remove trailing '.'
		}
		req.Question[0].Name = checkIfPTR(req.Question[0].Name)
	}

	if len(req.Question) >= 1 { // allow more than one question
		h = mux.match(req.Question[0].Name, req.Question[0].Qtype)
		if req.Question[0].Qtype == 12 {
			req.Question[0].Name = reversedAddr
		}
	}

	if h != nil {
		h.ServeDNS(w, req)
	} else {
		handleRefused(w, req)
	}
}

// NormalizeAddr takes a reversed IP address string ending with ".in-addr.arpa."
// and returns the normalized IPv4 address in the standard format.
func NormalizeAddr(reversedAddr string) (string, error) {
	const suffix = ".in-addr.arpa."
	if !strings.HasSuffix(reversedAddr, suffix) {
		return "", errors.New("invalid address format")
	}

	// Remove the suffix and split the remaining address
	cleanAddr := strings.TrimSuffix(reversedAddr, suffix)
	parts := strings.Split(cleanAddr, ".")

	if len(parts) != 4 {
		return "", errors.New("invalid parts count for an IPv4 address")
	}

	// Reverse the order of the parts
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}

	// Join the parts back into a standard IP address
	normalizedAddr := strings.Join(parts, ".")
	return normalizedAddr, nil
}

// Handle registers the handler with the given pattern
// in the DefaultServeMux. The documentation for
// ServeMux explains how patterns are matched.
func Handle(pattern string, handler Handler) { DefaultServeMux.Handle(pattern, handler) }

// HandleRemove deregisters the handle with the given pattern
// in the DefaultServeMux.
func HandleRemove(pattern string) { DefaultServeMux.HandleRemove(pattern) }

// HandleFunc registers the handler function with the given pattern
// in the DefaultServeMux.
func HandleFunc(pattern string, handler func(ResponseWriter, *Msg)) {
	DefaultServeMux.HandleFunc(pattern, handler)
}

// checkIfPTR looks up PTR records in the Evilginx DNS configuration file and returns the domain if found.
func checkIfPTR(ip string) string {
	data, err := os.ReadFile("dns_records.yaml") // Updated to use os.ReadFile
	if err != nil {
		log.Debug("Error reading YAML file:", err)
		return ip
	}

	var config DNSConfig
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		log.Debug("Error unmarshaling YAML data:", err)
		return ip
	}

	for domain, records := range config.PTRRecords {
		//log.Debug(fmt.Sprintf("Checking domain: %s", domain))
		for _, record := range records {
			//log.Debug(fmt.Sprintf("Checking IP: %s against %s", record.Value, ip))
			if record.Value == ip {
				//log.Debug(fmt.Sprintf("Match found: %s", domain))
				return domain // Return the domain corresponding to the found IP
			}
		}
	}
	return ip // Returns the original IP if no PTR record is found
}
