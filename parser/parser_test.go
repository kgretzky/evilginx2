package parser

import (
	"reflect"
	"testing"
)

// Tests in this package follow table-driven subtests via t.Run, use only the
// standard library, and avoid any network or filesystem access.

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []string
		wantErr bool
	}{
		{name: "empty", input: "", want: []string{}},
		{name: "whitespace only", input: "   \t  ", want: []string{}},
		{name: "simple tokens", input: "a b c", want: []string{"a", "b", "c"}},
		{name: "collapses repeated spaces", input: "a    b", want: []string{"a", "b"}},
		{name: "double quoted preserves spaces", input: `"hello world"`, want: []string{"hello world"}},
		{name: "single quoted preserves spaces", input: `'hello world'`, want: []string{"hello world"}},
		{name: "escaped space", input: `a\ b`, want: []string{"a b"}},
		{name: "single quote inside double quotes", input: `"it's"`, want: []string{"it's"}},
		{name: "mixed", input: `set host "my domain.com" 8080`, want: []string{"set", "host", "my domain.com", "8080"}},
		{name: "unterminated double quote", input: `"oops`, wantErr: true},
		{name: "unterminated single quote", input: `'oops`, wantErr: true},
		{name: "trailing escape", input: `abc\`, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Parse(%q) expected error, got nil (result %v)", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse(%q) unexpected error: %v", tt.input, err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Parse(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
