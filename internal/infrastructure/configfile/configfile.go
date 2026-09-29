// Package configfile reads the node's policy from /etc/vnm/config.yaml.
//
// Reading is strict: an unknown key, a malformed value or an invalid policy is
// an error, and nothing of a bad file is ever returned — the agent then keeps
// the last good state (ТЗ §7.3).
package configfile

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/lib4u/vnm/internal/domain/policy"
)

// Load reads and validates the policy in path.
func Load(path string) (policy.Config, error) {
	cfg, _, err := NewSource(path).Load()
	return cfg, err
}

// Source is the policy file the agent reads on every pass.
type Source struct {
	path string
}

// NewSource returns a Source reading path.
func NewSource(path string) *Source {
	return &Source{path: path}
}

// Load reads and validates the policy. The version is a hash of the file, so
// the agent re-plans only when the content changes.
func (s *Source) Load() (policy.Config, string, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return policy.Config{}, "", fmt.Errorf("read config: %w", err)
	}
	cfg, err := Parse(data)
	if err != nil {
		return policy.Config{}, "", err
	}
	sum := sha256.Sum256(data)
	return cfg, hex.EncodeToString(sum[:]), nil
}

// Parse decodes and validates a policy.
func Parse(data []byte) (policy.Config, error) {
	var dto fileDTO
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&dto); err != nil {
		return policy.Config{}, fmt.Errorf("%w: %w", policy.ErrInvalid, err)
	}
	// A second document would be read by nobody: it is a mistake, not a
	// comment.
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return policy.Config{}, fmt.Errorf("%w: the file holds more than one YAML document", policy.ErrInvalid)
	}

	cfg, err := toDomain(dto)
	if err != nil {
		return policy.Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return policy.Config{}, err
	}
	return cfg, nil
}

// converter maps the file to the domain, collecting every malformed value.
type converter struct {
	errs []error
}

func (c *converter) fail(format string, args ...any) {
	c.errs = append(c.errs, fmt.Errorf("%w: %s", policy.ErrInvalid, fmt.Sprintf(format, args...)))
}

func toDomain(dto fileDTO) (policy.Config, error) {
	var c converter
	cfg := policy.Config{
		Version: dto.Version,
		Mode:    c.mode(dto.Mode),
		Uplinks: dto.Uplinks,
		Geo:     policy.GeoFiles{GeoIP: dto.Geo.GeoIP, GeoSite: dto.Geo.GeoSite},
		DNS:     policy.DNS{Port: dto.DNS.Port, Upstreams: c.addrPorts("dns upstream", dto.DNS.Upstreams)},
		Exempt:  c.prefixes("exempt", dto.Exempt),
	}
	for _, e := range dto.Exits {
		cfg.Exits = append(cfg.Exits, c.exit(e))
	}
	for _, l := range dto.Lists {
		cfg.Lists = append(cfg.Lists, c.list(l))
	}
	for i, r := range dto.Policy {
		cfg.Rules = append(cfg.Rules, c.rule(i, r))
	}
	cfg.Guard = c.guard(dto.Guard)
	return cfg, errors.Join(c.errs...)
}

// guard maps the guard section. A guard without a mode is off: it is never
// switched on by default.
func (c *converter) guard(g guardDTO) policy.Guard {
	out := policy.Guard{Mode: policy.ModeOff}
	if g.Mode != "" {
		out.Mode = c.mode(g.Mode)
	}
	for i, r := range g.Rules {
		rule := policy.GuardRule{Lists: r.Lists, Log: r.Log}
		switch r.Action {
		case "drop":
			rule.Action = policy.GuardDrop
		case "reject":
			rule.Action = policy.GuardReject
		default:
			c.fail("guard rule %d: action %q is not drop or reject", i, r.Action)
		}
		out.Rules = append(out.Rules, rule)
	}
	return out
}

func (c *converter) mode(s string) policy.Mode {
	mode, ok := policy.ParseMode(s)
	if !ok {
		c.fail("mode %q is not one of %v", s, policy.Modes)
	}
	return mode
}

func (c *converter) exit(e exitDTO) policy.Exit {
	out := policy.Exit{
		Name: e.Name, Slot: e.Slot, Iface: e.Iface, Conf: e.Conf,
		Endpoints: c.addrPorts(fmt.Sprintf("exit %q: endpoint", e.Name), e.Endpoints),
	}
	if e.Health.URL != "" {
		u, err := url.Parse(e.Health.URL)
		if err != nil {
			c.fail("exit %q: health url %q: %v", e.Name, e.Health.URL, err)
		}
		out.Health.URL = u // scheme and host are the domain's to check
	}
	if r := e.Renew; r != nil {
		out.Renew = &policy.Renew{
			Command: r.Command,
			After:   c.duration(fmt.Sprintf("exit %q: renew after", e.Name), r.After, policy.DefaultRenewAfter),
			Every:   c.duration(fmt.Sprintf("exit %q: renew every", e.Name), r.Every, policy.DefaultRenewEvery),
		}
	}
	if e.Health.Expect != "" {
		re, err := regexp.Compile(e.Health.Expect)
		if err != nil {
			c.fail("exit %q: health expect: %v", e.Name, err)
		} else {
			out.Health.Expect = re
		}
	}
	return out
}

func (c *converter) list(l listDTO) policy.List {
	out := policy.List{
		Name:      l.Name,
		IP:        c.sources(l.Name, l.IP),
		ExtraCIDR: c.prefixes("list "+l.Name, l.ExtraCIDR),
		Domain:    c.sources(l.Name, l.Domain),
		Suffix:    l.Suffix,
		Bounds:    policy.DefaultBounds,
	}
	switch l.Checksum {
	case "", "sha256sum":
	case "none":
		out.Checksum = policy.ChecksumNone
		// Without a checksum only the list's own bounds tell a real list
		// from an error page or a cut-off file; defaults are too loose.
		if b := l.Bounds; b == nil || b.Min == nil || b.Max == nil {
			c.fail("list %q: checksum none needs bounds min and max of its own", l.Name)
		}
	default:
		c.fail("list %q: checksum %q is not sha256sum or none", l.Name, l.Checksum)
	}
	out.Refresh = c.duration(fmt.Sprintf("list %q: refresh", l.Name), l.Refresh, 0)
	if b := l.Bounds; b != nil {
		// A bound left out keeps its default; the others are the file's,
		// zero included — validation rejects what makes no sense.
		setIf(&out.Bounds.Min, b.Min)
		setIf(&out.Bounds.Max, b.Max)
		setIf(&out.Bounds.MaxChange, b.MaxChange)
	}
	return out
}

// duration parses a duration of the file; empty takes the default.
func (c *converter) duration(where, raw string, def time.Duration) time.Duration {
	if raw == "" {
		return def
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		c.fail("%s %q: %v", where, raw, err)
	}
	return d
}

func setIf[T any](dst *T, v *T) {
	if v != nil {
		*dst = *v
	}
}

// sourceKinds maps the "kind:" prefix of a source to its kind.
var sourceKinds = map[string]policy.SourceKind{
	"geoip":   policy.SourceGeoIP,
	"geosite": policy.SourceGeoSite,
	"file":    policy.SourceFile,
	"url":     policy.SourceURL,
}

func (c *converter) sources(list string, raw []string) []policy.Source {
	var out []policy.Source
	for _, s := range raw {
		prefix, value, ok := strings.Cut(s, ":")
		kind, known := sourceKinds[prefix]
		if !ok || !known || value == "" {
			c.fail("list %q: source %q must be geoip:, geosite:, file: or url:", list, s)
			continue
		}
		out = append(out, policy.Source{Kind: kind, Value: value})
	}
	return out
}

func (c *converter) addrPorts(where string, raw []string) []netip.AddrPort {
	var out []netip.AddrPort
	for _, s := range raw {
		ap, err := netip.ParseAddrPort(s)
		if err != nil {
			c.fail("%s %q: %v", where, s, err)
			continue
		}
		out = append(out, ap)
	}
	return out
}

func (c *converter) prefixes(where string, raw []string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range raw {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			c.fail("%s: range %q: %v", where, s, err)
			continue
		}
		out = append(out, p)
	}
	return out
}

func (c *converter) rule(i int, r ruleDTO) policy.Rule {
	out := policy.Rule{Lists: r.Lists}
	// Only exit takes an argument: "direct:warp" must never read as direct.
	switch kind, exit, hasArg := strings.Cut(r.Action, ":"); {
	case kind == "exit" && exit != "":
		out.Action = policy.Action{Kind: policy.ActionExit, Exit: exit}
	case kind == "block" && !hasArg:
		out.Action = policy.Action{Kind: policy.ActionBlock}
	case kind == "direct" && !hasArg:
		out.Action = policy.Action{Kind: policy.ActionDirect}
	default:
		c.fail("policy %d: action %q is not exit:<name>, block or direct", i, r.Action)
	}
	switch r.Fallback {
	case "":
	case "block":
		out.Fallback = policy.ActionBlock
	default:
		// Validate names the reason; here the value is simply not a fallback.
		c.fail("policy %d: fallback %q — only block is allowed", i, r.Fallback)
	}
	return out
}
