package policy_test

import (
	"errors"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/lib4u/vnm/internal/domain/policy"
	"github.com/lib4u/vnm/internal/testsupport"
)

func TestValidConfigPasses(t *testing.T) {
	if err := testsupport.Policy().Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidateRejects(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*policy.Config)
		want   string
	}{
		{"unknown version", func(c *policy.Config) { c.Version = 2 }, "version 2"},
		{"mode not set", func(c *policy.Config) { c.Mode = policy.ModeUnknown }, "mode is not set"},
		{"exit without block fallback", func(c *policy.Config) { c.Rules[0].Fallback = policy.ActionDirect }, "fallback block"},
		{"exit without fallback", func(c *policy.Config) { c.Rules[0].Fallback = policy.ActionUnknown }, "fallback block"},
		{"undefined exit", func(c *policy.Config) { c.Rules[0].Action.Exit = "tor" }, `exit "tor" is not defined`},
		{"undefined list", func(c *policy.Config) { c.Rules[0].Lists = []string{"cn"} }, `list "cn" is not defined`},
		{"block with fallback", func(c *policy.Config) {
			c.Rules[0].Action = policy.Action{Kind: policy.ActionBlock}
		}, "belong to exit rules only"},
		{"slot out of range", func(c *policy.Config) { c.Exits[0].Slot = policy.MaxExits }, "outside 0..4"},
		{"duplicate slot", func(c *policy.Config) {
			second := c.Exits[0]
			second.Name, second.Iface = "wg2", "wg2"
			c.Exits = append(c.Exits, second)
		}, "slot 0 is taken"},
		{"exit on uplink", func(c *policy.Config) { c.Exits[0].Iface = "ens3" }, "also an uplink"},
		{"name unsafe for nft", func(c *policy.Config) { c.Lists[0].Name = "ru-ip" }, `list name "ru-ip"`},
		{"geosite as address source", func(c *policy.Config) {
			c.Lists[0].IP = []policy.Source{{Kind: policy.SourceGeoSite, Value: "category-ru"}}
		}, "not an address source"},
		{"empty list", func(c *policy.Config) { c.Lists[1].Suffix = nil }, `list "ru_suffix" is empty`},
		{"bad suffix", func(c *policy.Config) { c.Lists[1].Suffix = []string{".ru"} }, "not a domain zone"},
		{"no endpoints", func(c *policy.Config) { c.Exits[0].Endpoints = nil }, "no endpoints"},
		{"no health probe", func(c *policy.Config) { c.Exits[0].Health = policy.Probe{} }, "health url and expect"},
		{"geoip source without geo url", func(c *policy.Config) { c.Geo.GeoIP = "" }, "geo geoip"},
		{"plain http geo url", func(c *policy.Config) {
			c.Geo.GeoIP = "http://geo.example.test/geoip.dat"
		}, "must be an https URL"},
		{"inverted bounds", func(c *policy.Config) { c.Lists[0].Bounds = policy.Bounds{Min: 10, Max: 5, MaxChange: 0.5} }, "bounds"},
		{"zero max change", func(c *policy.Config) { c.Lists[0].Bounds.MaxChange = 0 }, "bounds"},
		{"domain lists without upstreams", func(c *policy.Config) { c.DNS.Upstreams = nil }, "at least one upstream"},
		{"resolver on port 53", func(c *policy.Config) { c.DNS.Port = 53 }, "53 belongs to the host"},
		{"health url without host", func(c *policy.Config) { c.Exits[0].Health.URL, _ = url.Parse("https:warp") }, "must be https with a host"},
		{"plain http health url", func(c *policy.Config) { c.Exits[0].Health.URL, _ = url.Parse("http://www.cloudflare.com/") }, "must be https with a host"},
		{"guard without mode", func(c *policy.Config) { c.Guard.Mode = policy.ModeUnknown }, "guard: mode is not set"},
		{"renew with a relative command", func(c *policy.Config) {
			c.Exits[0].Renew = &policy.Renew{Command: []string{"vnm", "warp", "reissue"}, After: time.Hour, Every: time.Hour}
		}, "absolute path"},
		{"renew too early", func(c *policy.Config) {
			c.Exits[0].Renew = &policy.Renew{Command: []string{"/usr/local/bin/vnm"}, After: time.Minute, Every: time.Hour}
		}, "renew after"},
		{"renew too often", func(c *policy.Config) {
			c.Exits[0].Renew = &policy.Renew{Command: []string{"/usr/local/bin/vnm"}, After: time.Hour, Every: time.Minute}
		}, "renew every"},
		{"list twice in the rules", func(c *policy.Config) {
			c.Rules = append(c.Rules, policy.Rule{Lists: []string{"ru_ip"}, Action: policy.Action{Kind: policy.ActionBlock}})
		}, `list "ru_ip" is named more than once`},
		{"list twice in the guard", func(c *policy.Config) { c.Guard.Rules[0].Lists = []string{"scanners", "scanners"} }, `guard: list "scanners" is named more than once`},
		{"suffix too long", func(c *policy.Config) {
			c.Lists[1].Suffix = []string{strings.Repeat(strings.Repeat("a", 60)+".", 5) + "ru"}
		}, "not a domain zone"},
		{"guard on undefined list", func(c *policy.Config) { c.Guard.Rules[0].Lists = []string{"cn"} }, `guard rule 0: list "cn" is not defined`},
		{"guard on domain list", func(c *policy.Config) { c.Guard.Rules[0].Lists = []string{"ru_suffix"} }, "source addresses only"},
		{"guard without action", func(c *policy.Config) { c.Guard.Rules[0].Action = policy.GuardUnknown }, "guard rule 0: action is not set"},
		{"refresh too often", func(c *policy.Config) { c.Lists[0].Refresh = time.Minute }, "below 1h0m0s"},
		{"refresh without remote", func(c *policy.Config) { c.Lists[2].Refresh = time.Hour }, "reads nothing remote"},
		{"checksum none on geo", func(c *policy.Config) { c.Lists[0].Checksum = policy.ChecksumNone }, "geo files are always verified"},
		{"one url two ways", func(c *policy.Config) {
			c.Lists = append(c.Lists,
				policy.List{Name: "a", IP: []policy.Source{{Kind: policy.SourceURL, Value: "https://l.example.test/x"}}, Bounds: policy.DefaultBounds},
				policy.List{Name: "b", IP: []policy.Source{{Kind: policy.SourceURL, Value: "https://l.example.test/x"}}, Bounds: policy.DefaultBounds, Checksum: policy.ChecksumNone},
			)
		}, "another checksum setting"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testsupport.Policy()
			tt.mutate(&cfg)
			err := cfg.Validate()
			if !errors.Is(err, policy.ErrInvalid) {
				t.Fatalf("want policy.ErrInvalid, got %v", err)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error %q does not mention %q", err, tt.want)
			}
		})
	}
}

// One run must report every problem: an operator fixing a config one error per
// deploy is how a half-fixed config ends up on a node.
func TestValidateReportsAllProblems(t *testing.T) {
	cfg := testsupport.Policy()
	cfg.Version = 0
	cfg.Mode = policy.ModeUnknown
	cfg.Exits[0].Conf = ""

	err := cfg.Validate()
	for _, want := range []string{"version 0", "mode is not set", "conf is not set"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q:\n%v", want, err)
		}
	}
}

// A list the active parts do not apply is not needed; a list applied by the
// egress is strict wherever else it is used.
func TestListUses(t *testing.T) {
	cfg := testsupport.Policy()
	got := cfg.ListUses()
	want := map[string]policy.ListUse{"ru_ip": {Egress: true}, "ru_suffix": {Egress: true}, "scanners": {Guard: true}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("uses = %+v", got)
	}

	cfg.Mode = policy.ModeOff
	if got := cfg.ListUses(); !reflect.DeepEqual(got, map[string]policy.ListUse{"scanners": {Guard: true}}) {
		t.Fatalf("egress off: %+v", got)
	}
	cfg.Guard.Mode = policy.ModeOff
	if got := cfg.ListUses(); len(got) != 0 {
		t.Fatalf("both off: %+v", got)
	}
}

// One file is downloaded once, as often as its most demanding list asks.
func TestRemoteSources(t *testing.T) {
	cfg := testsupport.Policy()
	url := policy.Source{Kind: policy.SourceURL, Value: "https://l.example.test/scanners.list"}
	cfg.Lists = append(cfg.Lists,
		policy.List{Name: "a", IP: []policy.Source{url}, Checksum: policy.ChecksumNone, Refresh: 12 * time.Hour, Bounds: policy.DefaultBounds},
		policy.List{Name: "b", IP: []policy.Source{url}, Checksum: policy.ChecksumNone, Refresh: 2 * time.Hour, Bounds: policy.DefaultBounds},
	)
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	want := []policy.RemoteSource{
		{URL: testsupport.Geo.GeoIP, Format: policy.FormatGeoIP, Refresh: policy.DefaultRefresh},
		{URL: url.Value, Format: policy.FormatRanges, Checksum: policy.ChecksumNone, Refresh: 2 * time.Hour},
	}
	if got := cfg.RemoteSources(); !reflect.DeepEqual(got, want) {
		t.Fatalf("sources = %+v", got)
	}
}

func TestValidDomain(t *testing.T) {
	label := strings.Repeat("a", 63)
	longest := strings.Join([]string{label, label, label, strings.Repeat("a", 61)}, ".") // 253 bytes
	tests := []struct {
		in   string
		want bool
	}{
		{"vk.com", true},
		{"xn--p1ai", true},
		{longest, true},
		{longest + "a", false}, // past the 253 bytes of a DNS name
		{"", false},
		{".", false},
		{"VK.com", false}, // normalized first
		{"vk.com.", false},
		{"a..b", false},
		{"x\nserver=6.6.6.6", false},
		{"-a.ru", false},
	}
	for _, tt := range tests {
		if got := policy.ValidDomain(tt.in); got != tt.want {
			t.Errorf("ValidDomain(%q) = %t, want %t", tt.in, got, tt.want)
		}
	}
}

func TestNormalizeDomain(t *testing.T) {
	for in, want := range map[string]string{"VK.com.": "vk.com", "ya.ru": "ya.ru", ".": "", "": ""} {
		if got := policy.NormalizeDomain(in); got != want {
			t.Errorf("NormalizeDomain(%q) = %q, want %q", in, got, want)
		}
	}
}
