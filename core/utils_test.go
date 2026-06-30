package core

import (
	"testing"
	"time"
)

func TestParseDurationString(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    time.Duration
		wantErr bool
	}{
		{name: "full", input: "1d2h3m4s", want: 24*time.Hour + 2*time.Hour + 3*time.Minute + 4*time.Second},
		{name: "minutes only", input: "90m", want: 90 * time.Minute},
		{name: "hours and seconds", input: "2h30s", want: 2*time.Hour + 30*time.Second},
		{name: "empty is zero", input: "", want: 0},
		{name: "out of order", input: "1h2d", wantErr: true},
		{name: "unknown type", input: "5x", wantErr: true},
		{name: "must start with number", input: "d1", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseDurationString(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseDurationString(%q) expected error, got %v", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseDurationString(%q) unexpected error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Errorf("ParseDurationString(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestGetDurationString(t *testing.T) {
	now := time.Unix(1_000_000, 0)

	if got := GetDurationString(now, now.Add(1*time.Hour+2*time.Minute+3*time.Second)); got != "1h2m3s" {
		t.Errorf("GetDurationString future = %q, want %q", got, "1h2m3s")
	}
	if got := GetDurationString(now, now.Add(-time.Hour)); got != "" {
		t.Errorf("GetDurationString for past time should be empty, got %q", got)
	}
	if got := GetDurationString(now, now); got != "" {
		t.Errorf("GetDurationString for equal times should be empty, got %q", got)
	}
}

func TestGenRandomStringLengths(t *testing.T) {
	for _, n := range []int{0, 1, 8, 32} {
		if got := GenRandomString(n); len(got) != n {
			t.Errorf("GenRandomString(%d) length = %d, want %d", n, len(got), n)
		}
		if got := GenRandomAlphanumString(n); len(got) != n {
			t.Errorf("GenRandomAlphanumString(%d) length = %d, want %d", n, len(got), n)
		}
	}
}

func TestGenRandomTokenIsHexAndStable(t *testing.T) {
	tok := GenRandomToken()
	if len(tok) != 64 {
		t.Errorf("GenRandomToken length = %d, want 64 (sha256 hex)", len(tok))
	}
	for _, c := range tok {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Fatalf("GenRandomToken contains non-hex character %q in %q", c, tok)
		}
	}
	if GenRandomToken() == tok {
		t.Error("two GenRandomToken calls returned identical values (expected randomness)")
	}
}
