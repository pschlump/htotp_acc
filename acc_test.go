package main

import (
	"strings"
	"testing"
)

func TestInConfig(t *testing.T) {
	cfg := []ACConfigItem{
		{Name: "/example.com:bob@example.com"},
		{Name: "/other.org:alice@other.org"},
		{Name: "noslash.net:carol@noslash.net"},
	}

	tests := []struct {
		name     string
		lookFor  string
		expected int
	}{
		{"exact match with slash", "/example.com:bob@example.com", 0},
		{"match without leading slash", "example.com:bob@example.com", 0},
		{"second entry", "/other.org:alice@other.org", 1},
		{"stored without slash, queried with slash", "/noslash.net:carol@noslash.net", 2},
		{"stored without slash, queried without slash", "noslash.net:carol@noslash.net", 2},
		{"not found", "/missing.com:nobody@missing.com", -1},
		{"empty name", "", -1},
		{"partial match does not count", "example.com", -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := InConfig(cfg, tt.lookFor); got != tt.expected {
				t.Errorf("InConfig(cfg, %q) = %d, want %d", tt.lookFor, got, tt.expected)
			}
		})
	}
}

func TestInConfig_EmptySlice(t *testing.T) {
	if got := InConfig([]ACConfigItem{}, "/example.com:bob"); got != -1 {
		t.Errorf("InConfig on empty slice = %d, want -1", got)
	}
	if got := InConfig(nil, "/example.com:bob"); got != -1 {
		t.Errorf("InConfig on nil slice = %d, want -1", got)
	}
}

func TestInConfig_EmptyStoredName(t *testing.T) {
	// An entry with an empty Name must not panic and must not match.
	cfg := []ACConfigItem{{Name: ""}}
	if got := InConfig(cfg, "/example.com:bob"); got != -1 {
		t.Errorf("InConfig with empty stored name = %d, want -1", got)
	}
}

func TestResolveName(t *testing.T) {
	cfg := []ACConfigItem{
		{Name: "/example.com:bob@example.com"},
		{Name: "/example.com:alice@example.com"},
		{Name: "/myserver:phil"},
	}

	tests := []struct {
		name      string
		lookFor   string
		wantPos   int
		wantError string // substring of expected error; "" means no error
	}{
		{"exact with slash", "/myserver:phil", 2, ""},
		{"exact without slash", "myserver:phil", 2, ""},
		{"unique substring", "phil", 2, ""},
		{"unique substring of user", "bob@example", 0, ""},
		{"ambiguous substring", "example.com:", -1, "ambiguous"},
		{"not found", "nobody", -1, "not found"},
		{"empty name", "", -1, "not found"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pos, err := ResolveName(cfg, tt.lookFor)
			if tt.wantError == "" {
				if err != nil {
					t.Fatalf("ResolveName(%q) unexpected error: %s", tt.lookFor, err)
				}
				if pos != tt.wantPos {
					t.Errorf("ResolveName(%q) = %d, want %d", tt.lookFor, pos, tt.wantPos)
				}
			} else {
				if err == nil {
					t.Fatalf("ResolveName(%q) expected error containing %q, got pos=%d", tt.lookFor, tt.wantError, pos)
				}
				if !strings.Contains(err.Error(), tt.wantError) {
					t.Errorf("ResolveName(%q) error = %q, want substring %q", tt.lookFor, err, tt.wantError)
				}
			}
		})
	}
}
