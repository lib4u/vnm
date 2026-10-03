package configfile_test

import (
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/lib4u/vnm/internal/domain/policy"
	"github.com/lib4u/vnm/internal/infrastructure/configfile"
)

// The shipped config must load: it is what the installer puts on every node.
func TestShippedConfigLoads(t *testing.T) {
	cfg, err := configfile.Load(filepath.Join("..", "..", "..", "configs", "vnm.yaml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Mode != policy.ModeObserve {
		t.Errorf("a new node must start in observe, got mode %d", cfg.Mode)
	}
	ruIP, _ := cfg.List("ru_ip")
	if ruIP.Bounds != (policy.Bounds{Min: 5000, Max: 100000, MaxChange: 0.5}) {
		t.Errorf("ru_ip bounds = %+v", ruIP.Bounds)
	}
	domains, _ := cfg.List("ru_domain")
	if domains.Bounds != policy.DefaultBounds {
		t.Errorf("a list without bounds must get the defaults, got %+v", domains.Bounds)
	}
	if cfg.Guard.Mode != policy.ModeOff || len(cfg.Guard.Rules) != 1 {
		t.Errorf("the shipped guard must be present and off, got %+v", cfg.Guard)
	}
	if gov, _ := cfg.List("gov_networks"); gov.Checksum != policy.ChecksumNone {
		t.Errorf("gov_networks = %+v", gov)
	}
	warp, _ := cfg.Exit("warp")
	if r := warp.Renew; r == nil || r.After != 15*time.Minute || r.Every != time.Hour || r.Command[0] != "/usr/local/bin/vnm" {
		t.Errorf("warp renew = %+v", warp.Renew)
	}
	rule := cfg.Rules[0]
	if rule.Action != (policy.Action{Kind: policy.ActionExit, Exit: "warp"}) || rule.Fallback != policy.ActionBlock {
		t.Errorf("rule = %+v", rule)
	}
}

const minimal = `
version: 1
mode: enforce
geo: { geoip: "https://geo.example.test/geoip.dat" }
exits:
  - name: warp
    slot: 0
    iface: warp
    conf: /etc/vnm/exits/warp/warp.conf
    endpoints: ["162.159.192.1:2408"]
    health: { url: "https://www.cloudflare.com/cdn-cgi/trace", expect: "warp=on" }
lists:
  - name: ru_ip
    ip: ["geoip:ru"]
policy:
  - lists: [ru_ip]
    action: exit:warp
    fallback: block
`

func TestParseRejects(t *testing.T) {
	tests := []struct {
		name    string
		replace [2]string
		want    string
	}{
		{"unknown key — a typo must not be silently ignored", [2]string{"mode: enforce", "mode: enforce\nmodes: off"}, "modes"},
		{"unknown mode", [2]string{"mode: enforce", "mode: strict"}, "mode \"strict\""},
		{"unknown source kind", [2]string{`"geoip:ru"`, `"asn:12389"`}, "source \"asn:12389\""},
		{"bad endpoint", [2]string{`"162.159.192.1:2408"`, `"engage.cloudflareclient.com:2408"`}, "endpoint"},
		{"plain http probe", [2]string{"https://www.cloudflare.com", "http://www.cloudflare.com"}, "must be https with a host"},
		{"bad action", [2]string{"action: exit:warp", "action: tunnel"}, "action \"tunnel\""},
		{"direct fallback", [2]string{"fallback: block", "fallback: direct"}, "only block"},
		{"domain validation still runs", [2]string{"slot: 0", "slot: 7"}, "outside 0..4"},
		{"argument after direct", [2]string{"action: exit:warp", "action: direct:warp"}, `action "direct:warp"`},
		{"argument after block", [2]string{"action: exit:warp", `action: "block:"`}, `action "block:"`},
		{"exit without a name", [2]string{"action: exit:warp", `action: "exit:"`}, `action "exit:"`},
		{"second document", [2]string{"version: 1", "version: 1\n---\nmode: off"}, "more than one YAML document"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := strings.Replace(minimal, tt.replace[0], tt.replace[1], 1)
			_, err := configfile.Parse([]byte(data))
			if !errors.Is(err, policy.ErrInvalid) {
				t.Fatalf("want ErrInvalid, got %v", err)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error %q does not mention %q", err, tt.want)
			}
		})
	}
}

func TestParseMinimal(t *testing.T) {
	if _, err := configfile.Parse([]byte(minimal)); err != nil {
		t.Fatalf("Parse: %v", err)
	}
}

// guarded is minimal with a guard list and a guard.
var guarded = strings.Replace(minimal, "policy:\n", `  - name: scanners
    ip: ["url:https://lists.example.test/antiscanner.list"]
    checksum: none
    refresh: 12h
    bounds: { min: 50, max: 5000, max_change: 0.5 }
policy:
`, 1) + `guard:
  mode: observe
  rules:
    - lists: [scanners]
      action: drop
      log: true
`

func TestParseGuard(t *testing.T) {
	cfg, err := configfile.Parse([]byte(guarded))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := policy.Guard{
		Mode:  policy.ModeObserve,
		Rules: []policy.GuardRule{{Lists: []string{"scanners"}, Action: policy.GuardDrop, Log: true}},
	}
	if !reflect.DeepEqual(cfg.Guard, want) {
		t.Fatalf("guard = %+v", cfg.Guard)
	}
	scanners, _ := cfg.List("scanners")
	if scanners.Checksum != policy.ChecksumNone || scanners.Refresh != 12*time.Hour {
		t.Fatalf("list = %+v", scanners)
	}
}

// A file without a guard section, or a section without a mode, guards
// nothing: the guard is never on by default.
func TestGuardIsOffByDefault(t *testing.T) {
	for _, data := range []string{minimal, strings.Replace(guarded, "  mode: observe\n", "", 1)} {
		cfg, err := configfile.Parse([]byte(data))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Guard.Mode != policy.ModeOff {
			t.Fatalf("guard mode = %s", cfg.Guard.Mode)
		}
	}
}

// A file without a p2p section, or a section without a mode, refuses nothing;
// a section without a signature list refuses every signature there is.
func TestParseP2P(t *testing.T) {
	ban := policy.Ban{Threshold: policy.DefaultBanThreshold, Window: policy.DefaultBanWindow, TTL: policy.DefaultBanTTL}
	tests := []struct {
		name string
		data string
		want policy.P2P
	}{
		{"absent", minimal, policy.P2P{Mode: policy.ModeOff, Signatures: policy.Signatures, Ban: ban}},
		{"mode only", minimal + "p2p:\n  mode: observe\n", policy.P2P{Mode: policy.ModeObserve, Signatures: policy.Signatures, Ban: ban}},
		{"listed", minimal + "p2p:\n  mode: enforce\n  signatures: [utp_syn, dht]\n",
			policy.P2P{Mode: policy.ModeEnforce, Signatures: []policy.Signature{policy.SignatureUTPSyn, policy.SignatureDHT}, Ban: ban}},
		{"ndpi and ban", minimal + "p2p:\n  mode: observe\n  ndpi: {}\n  ban: { threshold: 30, window: 10m, ttl: 1h, scope: non_web }\n",
			policy.P2P{Mode: policy.ModeObserve, Signatures: policy.Signatures,
				NDPI: policy.NDPI{Enabled: true, Socket: policy.DefaultNDPISocket, PeerTTL: policy.DefaultPeerTTL},
				Ban:  policy.Ban{Threshold: 30, Window: 10 * time.Minute, TTL: time.Hour, NonWeb: true}}},
		{"ndpi off", minimal + "p2p:\n  mode: observe\n  ndpi: { enabled: false }\n",
			policy.P2P{Mode: policy.ModeObserve, Signatures: policy.Signatures,
				NDPI: policy.NDPI{Socket: policy.DefaultNDPISocket, PeerTTL: policy.DefaultPeerTTL}, Ban: ban}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := configfile.Parse([]byte(tt.data))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if !reflect.DeepEqual(cfg.P2P, tt.want) {
				t.Fatalf("p2p = %+v, want %+v", cfg.P2P, tt.want)
			}
		})
	}
}

func TestParseP2PRejects(t *testing.T) {
	for name, tail := range map[string]string{
		"unknown signature": "p2p:\n  mode: observe\n  signatures: [utp, dht]\n",
		"bad mode":          "p2p:\n  mode: strict\n",
		"unknown key":       "p2p:\n  mode: observe\n  dpi: true\n",
		"bad ban scope":     "p2p:\n  mode: observe\n  ban: { scope: some }\n",
		"ban threshold one": "p2p:\n  mode: observe\n  ban: { threshold: 1 }\n",
		"relative socket":   "p2p:\n  mode: observe\n  ndpi: { socket: ndpid.sock }\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := configfile.Parse([]byte(minimal + tail)); !errors.Is(err, policy.ErrInvalid) {
				t.Fatalf("error %v, want ErrInvalid", err)
			}
		})
	}
}

func TestParseGuardRejects(t *testing.T) {
	tests := []struct {
		name    string
		replace [2]string
		want    string
	}{
		{"checksum none without bounds", [2]string{"    bounds: { min: 50, max: 5000, max_change: 0.5 }\n", ""}, "needs bounds min and max of its own"},
		{"checksum none with empty bounds", [2]string{"bounds: { min: 50, max: 5000, max_change: 0.5 }", "bounds: {}"}, "needs bounds min and max of its own"},
		{"explicit zero max_change", [2]string{"max_change: 0.5 }", "max_change: 0 }"}, "bounds"},
		{"unknown checksum", [2]string{"checksum: none", "checksum: md5"}, `checksum "md5"`},
		{"bad refresh", [2]string{"refresh: 12h", "refresh: daily"}, `refresh "daily"`},
		{"bad guard action", [2]string{"action: drop", "action: ban"}, `action "ban" is not drop or reject`},
		{"bad guard mode", [2]string{"mode: observe", "mode: strict"}, `mode "strict"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := strings.Replace(guarded, tt.replace[0], tt.replace[1], 1)
			_, err := configfile.Parse([]byte(data))
			if !errors.Is(err, policy.ErrInvalid) || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error %v does not mention %q", err, tt.want)
			}
		})
	}
}
