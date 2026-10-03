// Package planner turns a policy into the kernel state that implements it.
//
// Plan is a pure function: everything it needs arrives in Input, and it touches
// neither the kernel nor the network. That is what lets the whole decision
// logic — which connection goes where — be tested without root, and what lets
// the agent compare "what should be" against "what is" byte for byte.
package planner

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"github.com/lib4u/vnm/internal/domain/netstate"
	"github.com/lib4u/vnm/internal/domain/policy"
)

// ErrUnresolvedList means a list with address sources arrived without ranges.
// Planning it as an empty set would silently let its destinations out
// directly — a leak (invariant I-1) — so the plan is refused instead.
var ErrUnresolvedList = errors.New("list has no resolved ranges")

// Input is everything a plan depends on.
type Input struct {
	Policy policy.Config
	// Ranges holds the resolved address ranges of each list, keyed by list
	// name: geoip entries, files and extra ranges already merged.
	Ranges map[string][]netip.Prefix
	// Domains holds the resolved domains of each list with domain entries.
	Domains map[string][]string
	// Uplinks are the interfaces of the default route, detected when the
	// policy leaves them empty.
	Uplinks []string
	Listen  netstate.Ports
	// Exits reports each exit's status by name. An exit missing from the map
	// has no interface and is dead.
	Exits map[string]ExitStatus
	// Resolver reports on the resolver; it is read only when the policy uses
	// domain lists.
	Resolver ResolverStatus
}

// ResolverStatus is what the agent currently knows about the resolver.
type ResolverStatus struct {
	// UID is the user the resolver queries its upstreams as: its own, never
	// root, or the redirect would let out every root process's DNS.
	UID uint32
	// Up means the resolver answers on its port.
	Up bool
}

// ExitStatus is what the agent currently knows about an exit.
type ExitStatus struct {
	// Present means the exit's interface exists, so it can carry a route.
	Present bool
	// Healthy means the exit passed its health check (ТЗ §4).
	Healthy bool
}

// Plan builds the desired kernel state: the destination policy while the
// egress is on, the guard and the p2p part while each is on — every part
// independent of the others.
func Plan(in Input) (netstate.State, error) {
	cfg := in.Policy
	if err := cfg.Validate(); err != nil {
		return netstate.State{}, err
	}
	if !cfg.EgressActive() && !cfg.Guard.Active() && !cfg.P2P.Active() {
		// Nothing on: the orchestrator removes every owned object.
		return netstate.State{}, nil
	}

	uplinks := cfg.Uplinks
	if len(uplinks) == 0 {
		uplinks = in.Uplinks
	}
	if len(uplinks) == 0 {
		return netstate.State{}, fmt.Errorf("%w: no uplink detected", policy.ErrInvalid)
	}
	state := netstate.State{
		Classify: netstate.Classify{
			Uplinks: slices.Clone(uplinks),
			Exempt:  exempt(cfg),
		},
	}
	if cfg.EgressActive() {
		if err := planEgress(&state, in); err != nil {
			return netstate.State{}, err
		}
	}
	if cfg.Guard.Active() {
		planGuard(&state, cfg, in.Ranges)
	}
	if cfg.P2P.Active() {
		planP2P(&state, cfg.P2P)
	}
	return state, nil
}

// planEgress adds the destination policy: classification, exits and the
// resolver.
func planEgress(state *netstate.State, in Input) error {
	cfg := in.Policy
	sets, decisions, err := classify(cfg, in.Ranges)
	if err != nil {
		return err
	}
	dns, err := resolver(cfg, sets, in.Domains)
	if err != nil {
		return err
	}
	c := &state.Classify
	c.Observe = cfg.Mode == policy.ModeObserve
	c.Listen = normalizePorts(in.Listen)
	c.Sets = sets
	c.Decisions = decisions
	c.DNSPort = dns.Port
	state.DNS = dns
	if dns.Enabled() {
		c.ResolverUID = in.Resolver.UID
		state.Health.ResolverUp = in.Resolver.Up
	}
	healthy := map[int]bool{}
	for _, e := range cfg.ExitsBySlot() {
		c.Exits = append(c.Exits, netstate.Exit{Slot: e.Slot, Iface: e.Iface})
		rules := netstate.ExitRules(e.Slot)
		state.Rules = append(state.Rules, rules[:]...)
		status := in.Exits[e.Name]
		if status.Present {
			state.Routes = append(state.Routes, netstate.Route{Table: netstate.ExitTable(e.Slot), Dev: e.Iface})
		}
		healthy[e.Slot] = status.Healthy
	}
	state.Health.DeadSlots = DeadSlots(c.Exits, healthy)
	return nil
}

// DeadSlots returns, in ascending order, the slots of the exits not known to
// be healthy: an exit missing from healthy is dead.
func DeadSlots(exits []netstate.Exit, healthy map[int]bool) []int {
	var dead []int
	for _, e := range exits {
		if !healthy[e.Slot] {
			dead = append(dead, e.Slot)
		}
	}
	slices.Sort(dead)
	return dead
}

// planGuard adds the guard. A list without resolved ranges fails open: its
// sets stay empty and guard nothing, and nothing else waits for it (G-4). A
// list the egress uses too shares its sets.
func planGuard(state *netstate.State, cfg policy.Config, ranges map[string][]netip.Prefix) {
	state.Guard.Observe = cfg.Guard.Mode == policy.ModeObserve
	c := &state.Classify
	for _, rule := range cfg.Guard.Rules {
		for _, name := range rule.Lists {
			list, _ := cfg.List(name) // Validate guarantees the list exists.
			for _, set := range listSets(list, ranges[name]) {
				if !slices.ContainsFunc(c.Sets, func(s netstate.AddrSet) bool { return s.Name == set.Name }) {
					c.Sets = append(c.Sets, set)
				}
				state.Guard.Rules = append(state.Guard.Rules, netstate.GuardRule{
					List:    name,
					Set:     set.Name,
					Family:  set.Family,
					Reject:  rule.Action == policy.GuardReject,
					Log:     rule.Log,
					Counter: guardCounterPrefix + set.Name,
				})
			}
		}
	}
}

// guardCounterPrefix names the guard's counters apart from the decisions'.
const guardCounterPrefix = "g_"

// planP2P adds the p2p part: one refusing rule per signature, in the order the
// policy names them (p2p ТЗ §3.1).
func planP2P(state *netstate.State, p policy.P2P) {
	state.P2P.Observe = p.Mode == policy.ModeObserve
	state.P2P.BanNonWeb = p.Ban.NonWeb
	for _, sig := range p.Signatures {
		state.P2P.Signatures = append(state.P2P.Signatures, netstate.P2PSignature{
			Name:    sig.String(),
			Counter: p2pCounterPrefix + sig.String(),
		})
	}
}

// p2pCounterPrefix names the p2p part's counters apart from the others'.
const p2pCounterPrefix = "p_"

// classify builds the destination sets and the ordered decisions over them.
// Only lists referenced by a rule become sets.
func classify(cfg policy.Config, ranges map[string][]netip.Prefix) ([]netstate.AddrSet, []netstate.Decision, error) {
	var sets []netstate.AddrSet
	var decisions []netstate.Decision
	defined := map[string]bool{}

	for i, rule := range cfg.Rules {
		for _, name := range rule.Lists {
			list, _ := cfg.List(name) // Validate guarantees the list exists.
			if list.HasAddressEntries() && len(ranges[name]) == 0 {
				return nil, nil, fmt.Errorf("list %q: %w", name, ErrUnresolvedList)
			}
			for _, set := range listSets(list, ranges[name]) {
				if !defined[set.Name] {
					defined[set.Name] = true
					sets = append(sets, set)
				}
				decisions = append(decisions, netstate.Decision{
					List:    name,
					Set:     set.Name,
					Family:  set.Family,
					Verdict: verdict(cfg, rule.Action, set.Family),
					Counter: fmt.Sprintf("r%d_%s", i, set.Name),
				})
			}
		}
	}
	return sets, decisions, nil
}

// Suffixes of the set names derived from a list.
const (
	staticSuffix4  = "_4"
	staticSuffix6  = "_6"
	dynamicSuffix4 = "_d4"
	dynamicSuffix6 = "_d6"
)

// listSets derives a list's sets: static ones from its ranges, dynamic ones
// for its domains, one per family each.
func listSets(list policy.List, ranges []netip.Prefix) []netstate.AddrSet {
	var out []netstate.AddrSet
	if list.HasAddressEntries() {
		v4, v6 := netstate.SplitByFamily(netstate.NormalizePrefixes(ranges))
		out = append(out,
			netstate.AddrSet{Name: list.Name + staticSuffix4, List: list.Name, Family: netstate.IPv4, Prefixes: v4},
			netstate.AddrSet{Name: list.Name + staticSuffix6, List: list.Name, Family: netstate.IPv6, Prefixes: v6},
		)
	}
	if list.HasDomainEntries() {
		out = append(out,
			netstate.AddrSet{Name: list.Name + dynamicSuffix4, List: list.Name, Family: netstate.IPv4, Dynamic: true},
			netstate.AddrSet{Name: list.Name + dynamicSuffix6, List: list.Name, Family: netstate.IPv6, Dynamic: true},
		)
	}
	return out
}

// resolver plans the resolver that fills the dynamic sets: one domain set per
// list with domain entries, taking the list's resolved domains. A list with
// domain sources but no domains is refused like an unresolved address list —
// its sets would silently stay empty.
func resolver(cfg policy.Config, sets []netstate.AddrSet, domains map[string][]string) (netstate.DNSState, error) {
	var dns netstate.DNSState
	for _, set := range sets {
		if !set.Dynamic || set.Family != netstate.IPv4 {
			continue
		}
		name := set.List
		if len(domains[name]) == 0 {
			return netstate.DNSState{}, fmt.Errorf("list %q: %w", name, ErrUnresolvedList)
		}
		dns.Sets = append(dns.Sets, netstate.DomainSet{
			Set4:    set.Name,
			Set6:    name + dynamicSuffix6,
			Domains: slices.Clone(domains[name]),
			NoAAAA:  cfg.Mode == policy.ModeEnforce && ipv4OnlyExit(cfg, name),
		})
	}
	if dns.Enabled() {
		dns.Port = cfg.DNS.Port
		dns.Upstreams = slices.Clone(cfg.DNS.Upstreams)
	}
	return dns, nil
}

// ipv4OnlyExit reports whether the rule deciding a list sends its IPv4 through
// an exit and so blocks its IPv6 (see verdict).
func ipv4OnlyExit(cfg policy.Config, list string) bool {
	for _, r := range cfg.Rules {
		if slices.Contains(r.Lists, list) {
			v4 := verdict(cfg, r.Action, netstate.IPv4)
			return v4 != netstate.VerdictBlock && v4 != netstate.VerdictDirect &&
				verdict(cfg, r.Action, netstate.IPv6) == netstate.VerdictBlock
		}
	}
	return false
}

// ListSizes returns how many address ranges each list has in a planned state —
// the reference the next resolved lists are checked against (ТЗ §7.4).
func ListSizes(s netstate.State) map[string]int {
	sizes := map[string]int{}
	for _, set := range s.Classify.Sets {
		if set.Dynamic {
			continue
		}
		sizes[set.List] += len(set.Prefixes)
	}
	return sizes
}

// verdict maps a rule's action to what a connection of the given family gets.
// Exits carry IPv4 only for now, so an IPv6 destination bound for an exit is
// blocked: the node's native IPv6 is as public as its IPv4 (ТЗ §3.5).
func verdict(cfg policy.Config, action policy.Action, family netstate.Family) netstate.Verdict {
	switch action.Kind {
	case policy.ActionExit:
		if family == netstate.IPv6 {
			return netstate.VerdictBlock
		}
		exit, _ := cfg.Exit(action.Exit) // Validate guarantees the exit exists.
		return netstate.VerdictExit(exit.Slot)
	case policy.ActionDirect:
		return netstate.VerdictDirect
	default:
		return netstate.VerdictBlock
	}
}

// exempt merges the configured exceptions, the exits' own endpoints (without
// them the encrypted exit traffic would be routed into itself), the resolver's
// upstreams and the ranges that never leave the node or its links.
func exempt(cfg policy.Config) []netip.Prefix {
	all := slices.Clone(cfg.Exempt)
	endpoints := slices.Clone(cfg.DNS.Upstreams)
	for _, e := range cfg.Exits {
		endpoints = append(endpoints, e.Endpoints...)
	}
	for _, ep := range endpoints {
		addr := ep.Addr().Unmap()
		all = append(all, netip.PrefixFrom(addr, addr.BitLen()))
	}
	all = append(all, localRanges...)
	return netstate.NormalizePrefixes(all)
}

// localRanges are special-purpose ranges that are never an internet
// destination (RFC 6890): loopback, private, link-local, CGNAT, multicast.
var localRanges = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

func normalizePorts(p netstate.Ports) netstate.Ports {
	return netstate.Ports{TCP: sortedUnique(p.TCP), UDP: sortedUnique(p.UDP)}
}

func sortedUnique(ports []uint16) []uint16 {
	out := slices.Clone(ports)
	slices.Sort(out)
	return slices.Compact(out)
}
