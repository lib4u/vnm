// Package policy is the destination policy of a node: which destinations are
// sent to which exit, blocked, or let through (ТЗ §3.2).
//
// The package knows nothing about the services running on the node (ТЗ §2.1):
// a policy is expressed only in destinations, exits and uplinks. It holds no
// file format either — the YAML mapping lives in infrastructure/configfile.
package policy

import (
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/lib4u/vnm/internal/domain/netstate"
)

// CurrentVersion is the only config schema version this build understands.
// An unknown version is an invalid config, never a best-effort read (ТЗ §7.3).
const CurrentVersion = 1

// MaxExits is how many exits fit into the ip rule priorities the agent owns
// (ТЗ §6.1).
const MaxExits = netstate.MaxSlots

// Mode is how the policy is applied.
type Mode uint8

const (
	ModeUnknown Mode = iota
	// ModeObserve classifies and counts, but changes no traffic (ТЗ §8).
	ModeObserve
	// ModeEnforce is the working mode.
	ModeEnforce
	// ModeOff removes the policy. It lifts invariant I-1, so it is only reached
	// through an explicit confirmation, never through a config default.
	ModeOff
)

// modeNames are the modes as written in the config and shown to operators.
var modeNames = map[Mode]string{ModeObserve: "observe", ModeEnforce: "enforce", ModeOff: "off"}

// Modes lists the valid modes in a stable order.
var Modes = []Mode{ModeObserve, ModeEnforce, ModeOff}

func (m Mode) String() string {
	if name, ok := modeNames[m]; ok {
		return name
	}
	return "unknown"
}

// ParseMode parses a mode name; ok is false for anything else.
func ParseMode(name string) (m Mode, ok bool) {
	for mode, n := range modeNames {
		if n == name {
			return mode, true
		}
	}
	return ModeUnknown, false
}

// ActionKind is what happens to a destination matched by a rule.
type ActionKind uint8

const (
	ActionUnknown ActionKind = iota
	// ActionExit sends the connection through an exit.
	ActionExit
	// ActionBlock rejects the connection.
	ActionBlock
	// ActionDirect lets the connection out through the uplink unchanged — an
	// explicit exception placed above a broader rule.
	ActionDirect
)

// Action is a rule's verdict. Exit names the exit and is set only for
// ActionExit.
type Action struct {
	Kind ActionKind
	Exit string
}

// Rule maps lists to an action. Rules are evaluated in order; the first match
// wins.
type Rule struct {
	Lists  []string
	Action Action
	// Fallback applies while the exit is unavailable. Only ActionBlock is
	// valid: a dead exit must never turn into a direct way out (invariant I-2).
	Fallback ActionKind
}

// SourceKind is where a list gets its entries from.
type SourceKind uint8

const (
	SourceUnknown SourceKind = iota
	// SourceGeoIP is a country code in geoip.dat ("geoip:ru").
	SourceGeoIP
	// SourceGeoSite is a category in geosite.dat ("geosite:category-ru").
	SourceGeoSite
	// SourceFile is a local file, one entry per line.
	SourceFile
	// SourceURL is a remote file, one entry per line.
	SourceURL
)

// Source is one origin of list entries.
type Source struct {
	Kind  SourceKind
	Value string
}

// List is a named set of destinations. The three kinds of entries are three
// different notions and are never merged (ТЗ §3.2): an address range, a domain
// from a catalogue, and a whole domain zone.
type List struct {
	Name string
	// IP sources yield address ranges, matched by destination address.
	IP []Source
	// ExtraCIDR are ranges added by hand, e.g. for upstream omissions.
	ExtraCIDR []netip.Prefix
	// Domain sources yield domains; they reach the network layer only as the
	// addresses those domains resolve to (ТЗ §5).
	Domain []Source
	// Suffix entries match a domain and everything under it ("ru", "xn--p1ai").
	Suffix []string
	// Bounds guard the list's address ranges against a broken update.
	Bounds Bounds
	// Checksum is how its url: sources are verified on download.
	Checksum Checksum
	// Refresh is how old the local copies of its remote sources may get;
	// zero means DefaultRefresh.
	Refresh time.Duration
}

// Bounds are the sanity limits of a list's resolved address ranges (ТЗ §7.4).
// A resolved list outside them is not applied: the previous one stays. The
// failure they guard against is a file that parses fine but lost most of its
// content — the policy would silently stop covering most destinations.
type Bounds struct {
	Min int
	Max int
	// MaxChange is the largest allowed relative change against the list
	// currently applied, as a fraction (0.5 = ±50 %).
	MaxChange float64
}

// DefaultBounds are the limits of a list that does not set its own.
var DefaultBounds = Bounds{Min: 1, Max: 1_000_000, MaxChange: 0.5}

// HasAddressEntries reports whether the list is matched by static ranges.
func (l List) HasAddressEntries() bool {
	return len(l.IP) > 0 || len(l.ExtraCIDR) > 0
}

// HasDomainEntries reports whether the list is matched by resolved domains.
func (l List) HasDomainEntries() bool {
	return len(l.Domain) > 0 || len(l.Suffix) > 0
}

// Probe is how an exit's health is checked: the body fetched from URL through
// the exit must match Expect. It is the only thing the agent knows about what
// sits behind an exit.
type Probe struct {
	URL    *url.URL
	Expect *regexp.Regexp
}

// Exit is a way out other than the uplink. The agent treats every exit as a
// plain WireGuard interface; what provider stands behind it is known only to
// the installer that wrote Conf.
type Exit struct {
	Name string
	// Slot fixes the exit's mark, routing table and rule priorities. It is set
	// explicitly so that reordering exits in the file never renumbers them.
	Slot  int
	Iface string
	// Conf is the WireGuard configuration the agent brings the interface up from.
	Conf string
	// Endpoints are tried in order when the current one stops working.
	Endpoints []netip.AddrPort
	Health    Probe
	// Renew, when set, replaces the exit's credentials once nothing else
	// brings it back: the agent runs a command it knows nothing about.
	Renew *Renew
}

// Renew is an exit's last resort: a command that issues it new credentials —
// for WARP a new registration — and rewrites Conf. The agent runs it when the
// exit has had no handshake for After, at most once per Every, and then
// recreates the interface from the new config.
type Renew struct {
	Command []string
	After   time.Duration
	Every   time.Duration
}

// Renew bounds: long enough to let the recovery ladder try everything else,
// rare enough not to trip a provider's registration limits.
const (
	DefaultRenewAfter = 15 * time.Minute
	DefaultRenewEvery = time.Hour
	MinRenewAfter     = 5 * time.Minute
	MinRenewEvery     = 30 * time.Minute
)

// DNS is the resolver that turns the domain lists into addresses (ТЗ §5): it
// answers queries redirected from downstream interfaces and the host's own,
// and puts the addresses of listed domains into the lists' sets.
type DNS struct {
	// Port is where the resolver listens. DNS from downstream interfaces is
	// redirected to it; the uplink never reaches it.
	Port uint16
	// Upstreams answer the resolver. They are exempt from the policy.
	Upstreams []netip.AddrPort
}

// GeoFiles are the URLs of the v2fly geo files that geoip: and geosite:
// sources read from.
type GeoFiles struct {
	GeoIP   string
	GeoSite string
}

// Config is a node's complete policy.
type Config struct {
	Version int
	Mode    Mode
	Geo     GeoFiles
	DNS     DNS
	// Uplinks are the interfaces of the default route. Empty means "detect".
	Uplinks []string
	Exits   []Exit
	Lists   []List
	Rules   []Rule
	// Exempt addresses are never touched by the policy, as destinations or
	// as guarded sources: management, monitoring. The exits' own endpoints
	// are added to it by the planner.
	Exempt []netip.Prefix
	Guard  Guard
	P2P    P2P
}

// Exit returns the exit with the given name.
func (c Config) Exit(name string) (Exit, bool) {
	for _, e := range c.Exits {
		if e.Name == name {
			return e, true
		}
	}
	return Exit{}, false
}

// ExitsBySlot returns the exits ordered by slot — the order rules, routes and
// statuses come out in, whatever the file order.
func (c Config) ExitsBySlot() []Exit {
	out := slices.Clone(c.Exits)
	slices.SortFunc(out, func(a, b Exit) int { return a.Slot - b.Slot })
	return out
}

// UsesDomains reports whether a rule applies a list with domain entries — the
// case in which the resolver runs.
func (c Config) UsesDomains() bool {
	for _, r := range c.Rules {
		for _, name := range r.Lists {
			if l, ok := c.List(name); ok && l.HasDomainEntries() {
				return true
			}
		}
	}
	return false
}

// List returns the list with the given name.
func (c Config) List(name string) (List, bool) {
	for _, l := range c.Lists {
		if l.Name == name {
			return l, true
		}
	}
	return List{}, false
}

// namePattern restricts list and exit names to what is safe inside nft set and
// counter names, which are derived from them.
var namePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,23}$`)

// ifacePattern is the Linux interface name rule: up to 15 bytes, no slash or
// whitespace.
var ifacePattern = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,15}$`)

// maxDomainLen is the longest domain name DNS carries, in its text form.
const maxDomainLen = 253

// ValidDomain reports whether s is a domain or zone the lists can hold:
// lowercase labels of letters, digits and hyphens, at most maxDomainLen bytes
// — a longer one is no domain, and would push a resolver's config line past
// its limit.
func ValidDomain(s string) bool { return len(s) <= maxDomainLen && suffixPattern.MatchString(s) }

// NormalizeDomain is the form a domain is listed in: lowercase, without the
// trailing dot of a fully qualified name. It validates nothing.
func NormalizeDomain(s string) string { return strings.TrimSuffix(strings.ToLower(s), ".") }

// suffixPattern accepts a DNS zone: labels of letters, digits and hyphens.
var suffixPattern = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
