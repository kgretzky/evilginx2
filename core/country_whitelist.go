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
	file_path string
}

func NewWhitelist(path string, dbPath string) (*Whitelist, error, *geoip2.Reader) {
	db, err := geoip2.Open(dbPath)
	if err != nil {
		return nil, err, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDONLY, 0644)
	if err != nil {
		return nil, err, db
	}
	defer f.Close()

	wl := &Whitelist{[]string{}, path}

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
			wl.countries = append(wl.countries, strings.ToUpper(l))
		}
	}
	log.Info("country whitelist: loaded %d country code", len(wl.countries))
	return wl, nil, db
}

func (wl *Whitelist)WriteToFile(){
	// Open a file for writing
	file, err := os.Create(wl.file_path)
	if err != nil {
		log.Error("%s", err)
		return
	}
	defer file.Close()

	// Write the list to the file
	for _, s := range wl.countries {
		_, err := file.WriteString(s + "\n")
		if err != nil {
			log.Error("%s", err)
			return
		}
	}
}

func (wl *Whitelist)AddCountry(c string){
	c = strings.Trim(c, " ")
	if len(c) > 0 {
		wl.countries = append(wl.countries, strings.ToUpper(c))
	}
	log.Info("country whitelist: %s country code added to whitelist", c)
	wl.WriteToFile()
}

func (wl *Whitelist)DeleteCountry(c string){
    out := make([]string, 0)
    for _, element := range wl.countries {
        if element != c {
            out = append(out, element)
        }
    }
    wl.countries = out
    log.Info("country whitelist: %s country code removed from whitelist", c)
    wl.WriteToFile()
}

func (wl *Whitelist) IsIPFromWhitelistedCountry(ip string, db *geoip2.Reader) bool {
	// If you are using strings that may be invalid, check that ip is not nil
	ipv4 := net.ParseIP(ip)
	record, err := db.City(ipv4)
	if err != nil {
		log.Error("%s", err)
		return true
	}
	if len(wl.countries) == 0 {
		return true
	}
	for _, c := range wl.countries {
		if c == record.Country.IsoCode {
			return true
		}
	}
	log.Info("[Country Whitelist] Blocked connection from %s", record.Country.IsoCode)
	return false
}
