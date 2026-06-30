package core

import (
	"regexp"
	"testing"
	"time"
)

func TestAllCookieAuthTokensCaptured(t *testing.T) {
	required := map[string][]*CookieAuthToken{
		".example.com": {
			{domain: ".example.com", name: "sid", optional: false},
		},
	}

	t.Run("all required captured", func(t *testing.T) {
		s, _ := NewSession("test")
		s.AddCookieAuthToken(".example.com", "sid", "value", "/", true, time.Time{})
		if !s.AllCookieAuthTokensCaptured(required) {
			t.Error("expected true when required token captured")
		}
	})

	t.Run("missing required", func(t *testing.T) {
		s, _ := NewSession("test")
		if s.AllCookieAuthTokensCaptured(required) {
			t.Error("expected false when required token missing")
		}
	})

	t.Run("optional token does not block completion", func(t *testing.T) {
		// A domain with one required and one optional token completes once the
		// required token is captured, even if the optional one is not.
		mixed := map[string][]*CookieAuthToken{
			".example.com": {
				{domain: ".example.com", name: "sid", optional: false},
				{domain: ".example.com", name: "opt", optional: true},
			},
		}
		s, _ := NewSession("test")
		s.AddCookieAuthToken(".example.com", "sid", "value", "/", true, time.Time{})
		if !s.AllCookieAuthTokensCaptured(mixed) {
			t.Error("expected true when the required token is captured and only an optional one is missing")
		}
	})

	t.Run("regex match", func(t *testing.T) {
		re := map[string][]*CookieAuthToken{
			".example.com": {
				{domain: ".example.com", re: regexp.MustCompile("^sess_"), optional: false},
			},
		}
		s, _ := NewSession("test")
		s.AddCookieAuthToken(".example.com", "sess_abc123", "value", "/", true, time.Time{})
		if !s.AllCookieAuthTokensCaptured(re) {
			t.Error("expected regex-based token to match captured cookie")
		}
	})
}

func TestSessionFinish(t *testing.T) {
	s, _ := NewSession("test")
	done := s.DoneSignal

	s.Finish(true)

	if !s.IsDone {
		t.Error("expected IsDone to be true after Finish")
	}
	if !s.IsAuthUrl {
		t.Error("expected IsAuthUrl to reflect the argument passed to Finish")
	}

	select {
	case <-done:
		// channel closed as expected
	default:
		t.Error("expected DoneSignal channel to be closed after Finish")
	}

	// Finish must be idempotent and must not panic on a second call.
	s.Finish(false)
	if !s.IsDone {
		t.Error("IsDone should remain true after a second Finish")
	}
}
