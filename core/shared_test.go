package core

import (
	"reflect"
	"testing"
)

func TestCombineHost(t *testing.T) {
	tests := []struct {
		sub    string
		domain string
		want   string
	}{
		{"login", "example.com", "login.example.com"},
		{"", "example.com", "example.com"},
		{"a.b", "example.com", "a.b.example.com"},
	}
	for _, tt := range tests {
		if got := combineHost(tt.sub, tt.domain); got != tt.want {
			t.Errorf("combineHost(%q, %q) = %q, want %q", tt.sub, tt.domain, got, tt.want)
		}
	}
}

func TestObfuscateDotsRoundTrip(t *testing.T) {
	inputs := []string{"example.com", "a.b.c.d", "no-dots-here", ""}
	for _, in := range inputs {
		obf := obfuscateDots(in)
		if got := removeObfuscatedDots(obf); got != in {
			t.Errorf("round-trip failed for %q: obfuscated=%q restored=%q", in, obf, got)
		}
	}
	if got := obfuscateDots("a.b"); got == "a.b" {
		t.Errorf("obfuscateDots(%q) should not contain literal dots: %q", "a.b", got)
	}
}

func TestStringExists(t *testing.T) {
	set := []string{"all", "unauth", "off"}
	if !stringExists("unauth", set) {
		t.Error("stringExists should find 'unauth'")
	}
	if stringExists("missing", set) {
		t.Error("stringExists should not find 'missing'")
	}
	if stringExists("x", nil) {
		t.Error("stringExists on nil slice should be false")
	}
}

func TestIntExists(t *testing.T) {
	set := []int{1, 3, 5}
	if !intExists(3, set) {
		t.Error("intExists should find 3")
	}
	if intExists(2, set) {
		t.Error("intExists should not find 2")
	}
}

func TestRemoveString(t *testing.T) {
	tests := []struct {
		in   []string
		rm   string
		want []string
	}{
		{[]string{"a", "b", "c"}, "b", []string{"a", "c"}},
		{[]string{"a", "b", "c"}, "missing", []string{"a", "b", "c"}},
		{[]string{"dup", "dup"}, "dup", []string{"dup"}}, // removes only first occurrence
	}
	for _, tt := range tests {
		in := append([]string{}, tt.in...)
		if got := removeString(tt.rm, in); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("removeString(%q, %v) = %v, want %v", tt.rm, tt.in, got, tt.want)
		}
	}
}

func TestTruncateString(t *testing.T) {
	if got := truncateString("short", 100); got != "short" {
		t.Errorf("truncateString should leave short strings unchanged, got %q", got)
	}
	long := "this-is-a-fairly-long-string-value"
	got := truncateString(long, 10)
	if len(got) >= len(long) {
		t.Errorf("truncateString(%q, 10) = %q, expected shorter than input", long, got)
	}
	if got == long {
		t.Error("expected truncation to change the long string")
	}
}
