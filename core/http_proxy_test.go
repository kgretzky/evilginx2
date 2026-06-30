package core

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// newTestProxy builds a minimal HttpProxy wired only to an in-memory Config.
// It deliberately avoids NewHttpProxy, which binds sockets and pulls in the full
// dependency graph; the pure rewriting/helper logic only reads p.cfg.
func newTestProxy(phishletName, phishDomain string, hosts []ProxyHost) *HttpProxy {
	cfg := &Config{
		phishletConfig: map[string]*PhishletConfig{
			phishletName: {Hostname: phishDomain, Enabled: true, Visible: true},
		},
		phishlets: map[string]*Phishlet{},
	}
	pl := &Phishlet{Name: phishletName, proxyHosts: hosts}
	cfg.phishlets[phishletName] = pl
	return &HttpProxy{cfg: cfg}
}

func TestPatchUrls(t *testing.T) {
	hosts := []ProxyHost{
		{phish_subdomain: "login", orig_subdomain: "accounts", domain: "google.com"},
	}
	// The phishing domain must use a real TLD; the URL-matching regex only
	// recognises hostnames ending in a known TLD.
	p := newTestProxy("test", "phishy.com", hosts)
	pl := p.cfg.phishlets["test"]

	t.Run("to phishing urls", func(t *testing.T) {
		body := []byte(`<a href="https://accounts.google.com/signin">go</a>`)
		got := string(p.patchUrls(pl, body, CONVERT_TO_PHISHING_URLS))
		if !strings.Contains(got, "login.phishy.com") {
			t.Errorf("expected phishing host in output, got: %s", got)
		}
		if strings.Contains(got, "accounts.google.com") {
			t.Errorf("original host should have been rewritten, got: %s", got)
		}
	})

	t.Run("to original urls", func(t *testing.T) {
		body := []byte(`<a href="https://login.phishy.com/signin">go</a>`)
		got := string(p.patchUrls(pl, body, CONVERT_TO_ORIGINAL_URLS))
		if !strings.Contains(got, "accounts.google.com") {
			t.Errorf("expected original host in output, got: %s", got)
		}
		if strings.Contains(got, "login.phishy.com") {
			t.Errorf("phishing host should have been rewritten back, got: %s", got)
		}
	})

	t.Run("unrelated host untouched", func(t *testing.T) {
		body := []byte(`<a href="https://example.org/x">go</a>`)
		got := string(p.patchUrls(pl, body, CONVERT_TO_PHISHING_URLS))
		if !strings.Contains(got, "example.org") {
			t.Errorf("unrelated host should be left as-is, got: %s", got)
		}
	})
}

func TestGetSessionCookieName(t *testing.T) {
	a := getSessionCookieName("google", "abcd1234")
	b := getSessionCookieName("google", "abcd1234")
	c := getSessionCookieName("github", "abcd1234")

	if a != b {
		t.Errorf("getSessionCookieName must be deterministic: %q != %q", a, b)
	}
	if a == c {
		t.Error("different phishlet names should yield different cookie names")
	}
	// format is "xxxx-xxxx": 8 hex chars with a dash at index 4
	if len(a) != 9 || a[4] != '-' {
		t.Fatalf("unexpected cookie name format: %q", a)
	}
	for i, ch := range a {
		if i == 4 {
			continue
		}
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')) {
			t.Errorf("non-hex character %q in cookie name %q", ch, a)
		}
	}
}

func TestGetContentType(t *testing.T) {
	tests := []struct {
		path string
		data []byte
		want string
	}{
		{"style.css", nil, "text/css"},
		{"app.js", nil, "application/javascript"},
		{"icon.svg", nil, "image/svg+xml"},
	}
	for _, tt := range tests {
		if got := getContentType(tt.path, tt.data); got != tt.want {
			t.Errorf("getContentType(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
	// unknown extension falls back to content sniffing
	if got := getContentType("page.unknown", []byte("<!DOCTYPE html><html></html>")); !strings.HasPrefix(got, "text/html") {
		t.Errorf("getContentType fallback = %q, want text/html prefix", got)
	}
}

func TestIsForwarderUrl(t *testing.T) {
	p := &HttpProxy{}

	// valid forwarder param: 5 bytes where byte[0] == sum(byte[1:])
	payload := []byte{1 + 2 + 3 + 4, 1, 2, 3, 4}
	enc := base64.RawURLEncoding.EncodeToString(payload)
	valid, _ := url.Parse("https://x.example/?q=" + enc)
	if !p.isForwarderUrl(valid) {
		t.Errorf("expected valid forwarder url to be detected: %s", valid.String())
	}

	// invalid checksum
	bad := []byte{99, 1, 2, 3, 4}
	encBad := base64.RawURLEncoding.EncodeToString(bad)
	invalid, _ := url.Parse("https://x.example/?q=" + encBad)
	if p.isForwarderUrl(invalid) {
		t.Error("expected forwarder url with bad checksum to be rejected")
	}

	// non-encoded query
	plain, _ := url.Parse("https://x.example/?q=hello")
	if p.isForwarderUrl(plain) {
		t.Error("expected plain query value to be rejected")
	}
}

func TestSetJSONVariable(t *testing.T) {
	out, err := SetJSONVariable([]byte(`{"a":1}`), "b", "x")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := string(out)
	if !strings.Contains(s, `"b":"x"`) {
		t.Errorf("expected new key in output, got: %s", s)
	}
	if !strings.Contains(s, `"a":1`) {
		t.Errorf("expected existing key preserved, got: %s", s)
	}

	if _, err := SetJSONVariable([]byte(`not json`), "b", "x"); err == nil {
		t.Error("expected error on invalid JSON input")
	}
}

// TestSessionMapConcurrentAccess exercises the session maps from many goroutines
// at once, mirroring goproxy's one-goroutine-per-connection handler model. It is
// meant to be run under `go test -race`: without the mutex guarding p.sessions /
// p.sids it reports a data race (or panics with "concurrent map ... write").
func TestSessionMapConcurrentAccess(t *testing.T) {
	p := &HttpProxy{
		sessions: make(map[string]*Session),
		sids:     make(map[string]int),
	}

	const workers = 50
	const iterations = 200

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				id := fmt.Sprintf("sess-%d-%d", w, i)
				s, _ := NewSession("test")
				p.addSession(id, s, w*iterations+i)
				if _, ok := p.getSession(id); !ok {
					t.Errorf("session %q not found immediately after addSession", id)
				}
				p.getSid(id)
				// also read a shared, possibly-not-yet-written key to mix reads/writes
				p.getSession("sess-0-0")
			}
		}(w)
	}
	wg.Wait()

	if _, ok := p.getSession("sess-0-0"); !ok {
		t.Error("expected sentinel session to be present after all workers finished")
	}
}
