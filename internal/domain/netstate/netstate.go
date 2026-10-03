// Package netstate is the kernel state the agent wants on the node: the marks,
// routing rules, routes and destination sets that implement a policy.
//
// It describes WHAT must be in the kernel, not how a particular tool writes it:
// the nft rendering lives in infrastructure. Every number here is part of the
// agent's ownership (ТЗ §6.1) — the agent creates, verifies and removes only
// objects identified by these values.
package netstate

import (
	"net/netip"
	"slices"
)

// Marks and routing identifiers owned by the agent.
//
// Exit marks start at 0xca6c (51820) so that slot 0 matches the mark Xray
// outbounds of hand-made WARP setups already put on their sockets: the contract "a
// socket marked 0xca6c goes out through exit 0" keeps working unchanged.
const (
	// exitMarkBase is the fwmark and conntrack mark of exit slot 0.
	exitMarkBase uint32 = 0xca6c
	// exitTableBase is the routing table of exit slot 0.
	exitTableBase = 51820
	// exitPriorityBase is the lookup rule priority of exit slot 0. Each slot
	// takes two consecutive priorities; slots 0..4 fill 1000–1009.
	exitPriorityBase = 1000

	// MarkDirect records the decision "leave through the uplink" on a
	// connection. It is never matched by a routing rule.
	MarkDirect uint32 = 0xca6a
	// MarkBlock records the decision "reject" on a connection.
	MarkBlock uint32 = 0xca6b

	// BypassBit is the agent's public contract: a packet whose socket carries
	// this bit is never classified (ТЗ §3.4). Who sets it is none of the
	// agent's business.
	BypassBit uint32 = 0x10000

	// ExitMarkMask is the part of a mark the exit rules compare. The bypass
	// bit lies outside it, so a socket can carry both: it then reaches the exit
	// without being classified — which is what the exit's own health probe
	// needs, or a dead exit's reject would refuse the probe that could revive
	// it.
	ExitMarkMask uint32 = 0xffff
)

// BypassToExit is the mark of a socket that must leave through an exit without
// being classified.
func BypassToExit(slot int) uint32 { return ExitMark(slot) | BypassBit }

// MaxSlots is how many exits fit into the owned rule priorities: two rules per
// slot in 1000–1009.
const MaxSlots = 5

// OwnedPriorities is the ip rule priority range the agent owns.
var OwnedPriorities = [2]int{exitPriorityBase, exitPriorityBase + 2*MaxSlots - 1}

// OwnedTables returns the routing tables the agent owns, one per slot.
func OwnedTables() []int {
	tables := make([]int, 0, MaxSlots)
	for slot := range MaxSlots {
		tables = append(tables, ExitTable(slot))
	}
	return tables
}

// ExitMark is the fwmark and conntrack mark of an exit slot.
func ExitMark(slot int) uint32 { return exitMarkBase + uint32(slot) }

// ExitTable is the routing table of an exit slot.
func ExitTable(slot int) int { return exitTableBase + slot }

// Family is an address family.
type Family uint8

const (
	FamilyUnknown Family = iota
	IPv4
	IPv6
)

// FamilyOf returns the family of a prefix.
func FamilyOf(p netip.Prefix) Family {
	if p.Addr().Is4() {
		return IPv4
	}
	return IPv6
}

// Verdict is what a matched connection gets.
type Verdict struct {
	// Mark is recorded on the connection: an exit mark, MarkBlock or MarkDirect.
	Mark uint32
}

// VerdictExit sends a connection through the exit in the given slot.
func VerdictExit(slot int) Verdict { return Verdict{Mark: ExitMark(slot)} }

var (
	// VerdictBlock rejects a connection.
	VerdictBlock = Verdict{Mark: MarkBlock}
	// VerdictDirect lets a connection out through the uplink.
	VerdictDirect = Verdict{Mark: MarkDirect}
)

// AddrSet is a named set of destination ranges of one family.
type AddrSet struct {
	Name string
	// List is the policy list the set derives from.
	List   string
	Family Family
	// Dynamic sets are filled at runtime by the resolver, with no timeout,
	// and keep their entries across replacements; static sets carry their
	// ranges here.
	Dynamic  bool
	Prefixes []netip.Prefix
}

// Decision classifies connections to one set. Decisions are evaluated in
// order; the first match wins.
type Decision struct {
	// List is the policy list the set derives from.
	List    string
	Set     string
	Family  Family
	Verdict Verdict
	// Counter names the counter that records matches — the only per-connection
	// trace the agent keeps (ТЗ §7.5).
	Counter string
}

// Exit is an exit as the kernel sees it.
type Exit struct {
	Slot  int
	Iface string
}

// Ports are the locally bound ports, per transport.
type Ports struct {
	TCP []uint16
	UDP []uint16
}

// Classify is the part of the state that decides a connection's fate: it
// changes when the policy, the lists or the local sockets change — never when
// an exit's health does. Its uplinks, exempt ranges and sets serve the guard
// too; without decisions it classifies nothing.
type Classify struct {
	// Observe records decisions in counters but lets every connection out
	// directly (ТЗ §8).
	Observe bool
	Uplinks []string
	Exits   []Exit
	Exempt  []netip.Prefix
	// Listen are the locally bound ports: a new connection from one of them is
	// a server answering a client whose conntrack entry expired (ТЗ §3.4).
	Listen    Ports
	Sets      []AddrSet
	Decisions []Decision
	// DNSPort, when set, redirects DNS — from downstream interfaces and from
	// the host itself — to the resolver listening on this port (ТЗ §5), for as
	// long as Health.ResolverUp holds.
	DNSPort uint16
	// ResolverUID is the user the resolver queries its upstreams as: the
	// host's redirect lets its packets through, or it would ask itself.
	ResolverUID uint32
}

// DNSState is the resolver part of the state; the zero value means no
// resolver runs.
type DNSState struct {
	Port      uint16
	Upstreams []netip.AddrPort
	Sets      []DomainSet
}

// DomainSet is a list's domains and the sets their addresses go into.
type DomainSet struct {
	Set4, Set6 string
	Domains    []string
	// NoAAAA drops the IPv6 addresses from the answers for these domains: the
	// list's IPv4 leaves through an exit while its IPv6 is blocked (exits carry
	// IPv4 only, ТЗ §3.5), and a client handed an IPv6 address would find the
	// site unreachable instead of reaching it through the exit over IPv4.
	NoAAAA bool
}

// Enabled reports whether a resolver is wanted.
func (d DNSState) Enabled() bool { return len(d.Sets) > 0 }

// RuleAction is what a routing rule does with a matched packet.
type RuleAction uint8

const (
	RuleActionUnknown RuleAction = iota
	// RuleLookup looks the packet up in Table.
	RuleLookup
	// RuleUnreachable fails the packet at once: a local socket gets
	// ENETUNREACH, forwarded traffic an ICMP unreachable.
	RuleUnreachable
	// RuleBlackhole and RuleProhibit are kernel actions the agent never
	// creates. They are modelled so that a rule someone else left in the owned
	// range can be told apart and removed exactly.
	RuleBlackhole
	RuleProhibit
)

// IPRule is one policy routing rule.
type IPRule struct {
	Priority int
	Mark     uint32
	// Mask is the part of the packet mark compared with Mark; zero compares
	// the whole mark.
	Mask   uint32
	Action RuleAction
	Table  int
	// Extra is whatever else a rule matches on or does that the fields above
	// cannot express — an input interface, a source, a goto — in the notation
	// of the adapter that read it. The agent never sets it, so a rule with
	// Extra is never one of the agent's; the adapter keeps it to delete exactly
	// that rule, since the kernel deletes the first rule that matches what a
	// deletion names and takes everything it leaves out as a wildcard.
	Extra string
}

// RouteType is the kernel's type of a route by its rtnetlink name:
// "unreachable", "blackhole", "throw"… The zero value is unicast, a route out
// through its device — the only type the agent creates.
type RouteType string

// RouteUnicast is the type of every route the agent creates.
const RouteUnicast RouteType = ""

// Route is a default route in an exit table.
type Route struct {
	Table int
	// Type and Metric are unicast and zero on every route the agent plans.
	// They are read so that a route someone else left in an owned table —
	// one without a device, or a second default behind the agent's — is told
	// apart from the agent's and deleted exactly.
	Type   RouteType
	Metric int
	// Dev is empty for a route without a device of its own: an unreachable
	// one, or one whose devices are in its nexthops.
	Dev string
	// Extra is whatever else tells a route apart that the fields above cannot
	// express — a TOS, a gateway, nexthops — in the notation of the adapter
	// that read it. Like IPRule.Extra, the agent never sets it: a route with
	// Extra is never the agent's, and the adapter keeps it to delete exactly
	// that route.
	Extra string
}

// State is the complete desired state. The zero State owns nothing: applying it
// removes every object the agent owns.
//
// Health never changes the classification or the rules; it is applied on its
// own, without replacing the table.
type State struct {
	Classify Classify
	Rules    []IPRule
	// Routes holds a default route for every exit whose interface exists.
	Routes []Route
	Health Health
	DNS    DNSState
	Guard  Guard
	P2P    P2P
	// Agent is the build of the agent that planned the state. A new build may
	// render the same state differently, so it applies the state anew once
	// instead of taking the old build's table for its own.
	Agent string `json:",omitempty"`
}

// Health is the part of the state that follows the agent's checks.
//
// A dead exit is handled in two layers (invariant I-2):
//
//   - DeadSlots lists the exits the agent declared dead: their connections are
//     rejected at once, locally and in transit;
//   - an exit whose interface is gone has no route, so its unreachable rule
//     fails the traffic even when no agent is running.
//
// DNS is redirected to the resolver only while ResolverUp holds: a resolver
// that died must not take the node's DNS down with it.
type Health struct {
	// DeadSlots are the slots of exits declared dead, in ascending order.
	DeadSlots []int
	// ResolverUp means the resolver answers on its port.
	ResolverUp bool
}

// Equal reports whether two healths are the same.
func (h Health) Equal(o Health) bool {
	return h.ResolverUp == o.ResolverUp && slices.Equal(h.DeadSlots, o.DeadSlots)
}

// Empty reports whether the state owns nothing. A planned state always has an
// uplink, so an empty uplink list means the zero State.
func (s State) Empty() bool {
	return len(s.Classify.Uplinks) == 0
}
