package core

import (
	"bufio"
	"github.com/kgretzky/evilginx2/log"
	"net"
	"os"
	"strings"
	geoip2 "github.com/oschwald/geoip2-golang"
)

type Whitelist struct {
	countries []string
}

func NewWhitelist(path string, dbPath string) (*Whitelist, error, *geoip2.Reader) {
	db, err := geoip2.Open(dbPath)
	if err != nil {
		return nil, err, nil
	}
	defer db.Close()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDONLY, 0644)
	if err != nil {
		return nil, err, db
	}
	defer f.Close()

	wl := &Whitelist{[]string{}}

	fs := bufio.NewScanner(f)
	fs.Split(bufio.ScanLines)

	for fs.Scan() {
		l := fs.Text()
		// remove comments
		if n := strings.Index(l, ";"); n > -1 {
			l = l[:n]
		}
		l = strings.Trim(l, " ")
		if len(l) > 0 {
			wl.countries = append(wl.countries, l)
		}
	}
	log.Info("country whitelist: loaded %d country code", len(wl.countries))
	return wl, nil, db
}

func (wl *Whitelist) IsIPFromWhitelistedCountry(ip string, db *geoip2.Reader) bool {
	// If you are using strings that may be invalid, check that ip is not nil
	ipv4 := net.ParseIP(ip)
	record, err := db.City(ipv4)
	if err != nil {
		return true
	}
	log.Info("should be ranging")
	for c := range wl.countries {
		log.Info("c = %s", c)
		log.Info("record = %s", record.Country.IsoCode)
		if wl.countries[c] == record.Country.IsoCode {
			return true
		}
	}
	return false
}
