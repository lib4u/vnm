package listcache

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/lib4u/vnm/internal/domain/policy"
)

func TestParseRange(t *testing.T) {
	tests := []struct {
		in   string
		want string // "" for an error
	}{
		{"5.8.0.0/19", "5.8.0.0/19"},
		{"77.88.55.88", "77.88.55.88/32"},
		{"2001:db8::/32", "2001:db8::/32"},
		{"195.182.151.212/29", "195.182.151.208/29"}, // as government_networks has it
		{"2001:db8::1/32", "2001:db8::/32"},
		{"fe80::1%eth0", ""}, // a zone names a link, not a destination
		{"fe80::1%eth0/64", ""},
		{"example.com", ""},
	}
	for _, tt := range tests {
		got, err := parseRange(tt.in)
		switch {
		case tt.want == "" && err == nil:
			t.Errorf("parseRange(%q) = %v, want an error", tt.in, got)
		case tt.want != "" && (err != nil || got != netip.MustParsePrefix(tt.want)):
			t.Errorf("parseRange(%q) = %v, %v; want %s", tt.in, got, err, tt.want)
		}
	}
}

func TestParses(t *testing.T) {
	tests := []struct {
		name string
		data string
		f    policy.Format
		ok   bool
	}{
		{"ranges", "# AS61280\n185.224.228.0/24\n", policy.FormatRanges, true},
		{"cut off in the last line", "185.224.228.0/24\n10.0.0.0/2", policy.FormatRanges, false},
		{"no final newline, transfer known whole", "185.224.228.0/24\n10.0.0.0/24", policy.FormatRanges, true},
		{"host bits, as real lists have them", "195.182.151.212/29\n", policy.FormatRanges, true},
		{"no entries", "# nothing\n", policy.FormatRanges, false},
		{"domains", "VK.com.\ngosuslugi.ru\n", policy.FormatDomains, true},
		{"a config line", "vk.com\nserver=6.6.6.6\n", policy.FormatDomains, false},
		{"a lone dot", ".\n", policy.FormatDomains, false},
		{"longer than a domain", strings.Repeat("a.", 127) + "ru\n", policy.FormatDomains, false},
	}
	for _, tt := range tests {
		whole := strings.Contains(tt.name, "known whole")
		if err := parses([]byte(tt.data), tt.f, whole); (err == nil) != tt.ok {
			t.Errorf("%s: err = %v, want ok %t", tt.name, err, tt.ok)
		}
	}
}

// A geosite value is held to the same rule as a line of a domain list.
func TestDomain(t *testing.T) {
	for in, want := range map[string]string{"VK.com.": "vk.com", "xn--p1ai": "xn--p1ai"} {
		if got, err := domain(in); err != nil || got != want {
			t.Errorf("domain(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", ".", "x\nserver=6.6.6.6", "vk.com/", strings.Repeat("a", 1172)} {
		if got, err := domain(in); err == nil {
			t.Errorf("domain(%q) = %q, want an error", in, got)
		}
	}
}
