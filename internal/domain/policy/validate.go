package policy

import (
	"errors"
	"fmt"
	"net/url"
	"path"
	"slices"
)

// ErrInvalid marks every validation failure, so callers can tell a bad config
// from an I/O error without parsing messages.
var ErrInvalid = errors.New("invalid policy")

// problems collects validation failures so that one run reports all of them.
type problems []error

func (p *problems) add(format string, args ...any) {
	*p = append(*p, fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...)))
}

// Validate reports every problem in the config at once. A config that fails
// validation is never applied, not even partially (ТЗ §7.3).
func (c Config) Validate() error {
	var p problems
	if c.Version != CurrentVersion {
		p.add("version %d is not supported (want %d)", c.Version, CurrentVersion)
	}
	if c.Mode == ModeUnknown {
		p.add("mode is not set")
	}
	for _, iface := range c.Uplinks {
		if !ifacePattern.MatchString(iface) {
			p.add("uplink %q is not an interface name", iface)
		}
	}
	for _, r := range c.Exempt {
		if !r.IsValid() {
			p.add("exempt range %v is not valid", r)
		}
	}
	c.validateExits(&p)
	c.validateLists(&p)
	c.validateRemote(&p)
	c.validateGeo(&p)
	c.validateDNS(&p)
	c.validateRules(&p)
	c.validateGuard(&p)
	return errors.Join(p...)
}

func (c Config) validateExits(p *problems) {
	if len(c.Exits) > MaxExits {
		p.add("%d exits configured, at most %d fit into the owned rule priorities", len(c.Exits), MaxExits)
	}
	uplinks := map[string]bool{}
	for _, u := range c.Uplinks {
		uplinks[u] = true
	}
	names := map[string]bool{}
	slots := map[int]bool{}
	ifaces := map[string]bool{}
	for _, e := range c.Exits {
		switch {
		case !namePattern.MatchString(e.Name):
			p.add("exit name %q must match %s", e.Name, namePattern)
		case names[e.Name]:
			p.add("exit %q is defined twice", e.Name)
		}
		names[e.Name] = true

		switch {
		case e.Slot < 0 || e.Slot >= MaxExits:
			p.add("exit %q: slot %d is outside 0..%d", e.Name, e.Slot, MaxExits-1)
		case slots[e.Slot]:
			p.add("exit %q: slot %d is taken by another exit", e.Name, e.Slot)
		}
		slots[e.Slot] = true

		switch {
		case !ifacePattern.MatchString(e.Iface):
			p.add("exit %q: %q is not an interface name", e.Name, e.Iface)
		case ifaces[e.Iface]:
			p.add("exit %q: interface %q is used by another exit", e.Name, e.Iface)
		case uplinks[e.Iface]:
			p.add("exit %q: interface %q is also an uplink", e.Name, e.Iface)
		}
		ifaces[e.Iface] = true

		if e.Conf == "" {
			p.add("exit %q: conf is not set", e.Name)
		}
		if len(e.Endpoints) == 0 {
			p.add("exit %q: no endpoints", e.Name)
		}
		for _, ep := range e.Endpoints {
			if !ep.IsValid() {
				p.add("exit %q: endpoint %v is not valid", e.Name, ep)
			}
		}
		if r := e.Renew; r != nil {
			switch {
			case len(r.Command) == 0 || !path.IsAbs(r.Command[0]):
				p.add("exit %q: renew command must start with an absolute path", e.Name)
			case r.After < MinRenewAfter:
				p.add("exit %q: renew after %v is below %v", e.Name, r.After, MinRenewAfter)
			case r.Every < MinRenewEvery:
				p.add("exit %q: renew every %v is below %v", e.Name, r.Every, MinRenewEvery)
			}
		}
		switch {
		case e.Health.URL == nil || e.Health.Expect == nil:
			p.add("exit %q: health url and expect are both required", e.Name)
		case !isHTTPS(e.Health.URL):
			p.add("exit %q: health url %q must be https with a host", e.Name, e.Health.URL)
		}
	}
}

func (c Config) validateLists(p *problems) {
	names := map[string]bool{}
	for _, l := range c.Lists {
		switch {
		case !namePattern.MatchString(l.Name):
			p.add("list name %q must match %s", l.Name, namePattern)
		case names[l.Name]:
			p.add("list %q is defined twice", l.Name)
		}
		names[l.Name] = true

		if !l.HasAddressEntries() && !l.HasDomainEntries() {
			p.add("list %q is empty", l.Name)
		}
		for _, s := range l.IP {
			if !s.yieldsAddresses() {
				p.add("list %q: %q is not an address source", l.Name, s.Value)
			}
		}
		for _, s := range l.Domain {
			if !s.yieldsDomains() {
				p.add("list %q: %q is not a domain source", l.Name, s.Value)
			}
		}
		for _, r := range l.ExtraCIDR {
			if !r.IsValid() {
				p.add("list %q: range %v is not valid", l.Name, r)
			}
		}
		for _, s := range l.Suffix {
			if !ValidDomain(s) {
				p.add("list %q: suffix %q is not a domain zone", l.Name, s)
			}
		}
		if b := l.Bounds; b.Min < 1 || b.Max < b.Min || b.MaxChange <= 0 || b.MaxChange > 1 {
			p.add("list %q: bounds %+v must have 1 <= min <= max and 0 < max_change <= 1", l.Name, b)
		}
	}
}

// validateGeo requires the geo file URL of every geo source kind in use.
func (c Config) validateGeo(p *problems) {
	used := map[SourceKind]bool{}
	for _, l := range c.Lists {
		for _, s := range slices.Concat(l.IP, l.Domain) {
			used[s.Kind] = true
		}
	}
	check := func(kind SourceKind, name, rawURL string) {
		if !used[kind] {
			return
		}
		if !isHTTPSString(rawURL) {
			p.add("geo %s: %q must be an https URL — a list source is fetched onto every node", name, rawURL)
		}
	}
	check(SourceGeoIP, "geoip", c.Geo.GeoIP)
	check(SourceGeoSite, "geosite", c.Geo.GeoSite)
	for _, l := range c.Lists {
		for _, s := range slices.Concat(l.IP, l.Domain) {
			if s.Kind == SourceURL && !isHTTPSString(s.Value) {
				p.add("list %q: url %q must be https", l.Name, s.Value)
			}
		}
	}
}

// validateDNS requires a resolver whenever a rule uses domain lists. Port 53
// is left to the host's resolver.
func (c Config) validateDNS(p *problems) {
	if !c.UsesDomains() {
		return
	}
	if c.DNS.Port < 1024 {
		p.add("dns: port %d must be 1024 or above — 53 belongs to the host's resolver", c.DNS.Port)
	}
	if len(c.DNS.Upstreams) == 0 {
		p.add("dns: domain lists need at least one upstream")
	}
	for _, u := range c.DNS.Upstreams {
		if !u.IsValid() {
			p.add("dns: upstream %v is not valid", u)
		}
	}
}

func isHTTPSString(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && isHTTPS(u)
}

func isHTTPS(u *url.URL) bool {
	return u.Scheme == "https" && u.Hostname() != ""
}

func (c Config) validateRules(p *problems) {
	lists := make([][]string, 0, len(c.Rules))
	for _, r := range c.Rules {
		lists = append(lists, r.Lists)
	}
	for _, name := range repeated(lists) {
		// The first rule naming a list decides for it; a second one would
		// never match and would share its counters.
		p.add("list %q is named more than once in the rules", name)
	}
	for i, r := range c.Rules {
		if len(r.Lists) == 0 {
			p.add("rule %d names no lists", i)
		}
		for _, name := range r.Lists {
			if _, ok := c.List(name); !ok {
				p.add("rule %d: list %q is not defined", i, name)
			}
		}

		switch r.Action.Kind {
		case ActionExit:
			if _, ok := c.Exit(r.Action.Exit); !ok {
				p.add("rule %d: exit %q is not defined", i, r.Action.Exit)
			}
			if r.Fallback != ActionBlock {
				p.add("rule %d: an exit needs fallback block — a dead exit must not become a direct way out", i)
			}
		case ActionBlock, ActionDirect:
			if r.Action.Exit != "" || r.Fallback != ActionUnknown {
				p.add("rule %d: exit and fallback belong to exit rules only", i)
			}
		default:
			p.add("rule %d: action is not set", i)
		}
	}
}

// yieldsAddresses reports whether the source can feed an ip list.
func (s Source) yieldsAddresses() bool {
	switch s.Kind {
	case SourceGeoIP, SourceFile, SourceURL:
		return s.Value != ""
	default:
		return false
	}
}

// yieldsDomains reports whether the source can feed a domain list.
func (s Source) yieldsDomains() bool {
	switch s.Kind {
	case SourceGeoSite, SourceFile, SourceURL:
		return s.Value != ""
	default:
		return false
	}
}

// repeated returns the names that occur more than once across the groups, in
// order of their second occurrence.
func repeated(groups [][]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, g := range groups {
		for _, name := range g {
			if seen[name] && !slices.Contains(out, name) {
				out = append(out, name)
			}
			seen[name] = true
		}
	}
	return out
}
