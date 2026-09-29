// Package nftables writes the classification part of the desired state as an
// nft ruleset, and applies it.
//
// Everything lives in one table, "inet vnm", which the agent owns entirely
// (ТЗ §6.1). Other tables — ufw, Docker, iptables rules of other services —
// are never read into or written by this package.
//
// How a connection is classified (ТЗ §3.1):
//
//   - only the first packet of a new connection is classified, and only if the
//     connection carries no decision yet; the decision is stored in the
//     conntrack mark and restored onto every later packet of the original
//     direction. Replies are never marked, so traffic answering a client —
//     whatever its address — is never rerouted (invariant I-3);
//   - forwarded traffic is classified only when it did not arrive from an
//     uplink or an exit, i.e. it comes from some local downstream interface;
//   - locally generated traffic is classified in a route-type output chain, so
//     a changed mark reroutes the packet;
//   - a socket carrying the bypass bit, an exempt destination, or (for local
//     traffic) a source port the node listens on, is decided "direct";
//   - a connection bound for an exit the agent declared dead is rejected at
//     once, before it is rerouted: the kernel would otherwise drop a rerouted
//     local packet silently and the socket would wait for a timeout.
package nftables

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/lib4u/vnm/internal/domain/netstate"
)

// Table is the agent's nft table.
const (
	TableFamily = "inet"
	TableName   = "vnm"
)

// Fixed set and counter names. List sets are prefixed with "l_" so that no list
// name can collide with them.
const (
	setUplinks   = "uplinks"
	setExits     = "exits"
	setExempt4   = "exempt4"
	setExempt6   = "exempt6"
	setListenTCP = "listen_tcp"
	setListenUDP = "listen_udp"
	setDeadExits = "dead_exits"
	setDNSPorts  = "dns_ports"
	listPrefix   = "l_"

	counterListenBypass = "listen_bypass"
	counterBlocked      = "blocked"
	counterExitDown     = "exit_down"
)

// Render returns the definition of the agent's table for a state, less its
// health. The output is deterministic: equal inputs render to byte-identical
// text.
func Render(s netstate.State) string { return render(s, AllFeatures) }

func render(s netstate.State, f Features) string {
	c := s.Classify
	w := &writer{f: f}
	w.line(0, "table %s %s {", TableFamily, TableName)
	renderSets(w, c)
	renderCounters(w, s)
	if c.Classifies() {
		renderDecide(w, c)
		renderClassify(w, c)
	}
	if len(c.Exits) > 0 {
		renderExits(w)
	}
	if c.DNSPort != 0 {
		renderDNS(w, c)
	}
	if s.Guard.Active() {
		renderGuard(w, s.Guard)
	}
	w.line(0, "}")
	return w.String()
}

// Script returns an nft script that creates the agent's table with the state
// and its health, for a node that has no table yet. The agent replaces an
// existing table through Firewall.Apply, which keeps what must survive.
func Script(s netstate.State) string {
	return replaceScript(s, inventory{}, AllFeatures)
}

// dnsPort is the port whose traffic is redirected to the resolver.
const dnsPort = 53

// HealthScript returns an nft script that applies the health: which exits are
// dead, and whether DNS goes to the resolver. It touches only the health sets,
// so a health change never rewrites the ruleset.
func HealthScript(h netstate.Health) string {
	marks := make([]string, 0, len(h.DeadSlots))
	for _, slot := range h.DeadSlots {
		marks = append(marks, mark(netstate.ExitMark(slot)))
	}
	var dns []string
	if h.ResolverUp {
		dns = []string{fmt.Sprint(dnsPort)}
	}
	w := &writer{}
	w.fill(setDeadExits, marks)
	w.fill(setDNSPorts, dns)
	return w.String()
}

func renderSets(w *writer, c netstate.Classify) {
	exempt4, exempt6 := netstate.SplitByFamily(c.Exempt)

	w.set(setUplinks, "ifname", "", quoted(c.Uplinks))
	w.set(setExits, "ifname", "", quoted(exitIfaces(c.Exits)))
	w.set(setExempt4, "ipv4_addr", "interval", prefixes(exempt4))
	w.set(setExempt6, "ipv6_addr", "interval", prefixes(exempt6))
	w.set(setListenTCP, "inet_service", "", ports(c.Listen.TCP))
	w.set(setListenUDP, "inet_service", "", ports(c.Listen.UDP))
	w.set(setDeadExits, "mark", "", nil)
	w.set(setDNSPorts, "inet_service", "", nil)

	for _, s := range c.Sets {
		// A dynamic set holds single addresses the resolver adds. They carry no
		// timeout: the resolver cannot refresh one, and an entry expiring while
		// a client still uses its cached answer would let that connection out
		// directly. Stale entries err towards the exit, never towards a leak.
		flags := "interval"
		if s.Dynamic {
			flags = ""
		}
		w.set(SetName(s.Name), addrType(s.Family), flags, prefixes(s.Prefixes))
	}
}

func renderCounters(w *writer, s netstate.State) {
	for _, name := range counters(s) {
		w.line(1, "counter %s {}", name)
	}
}

// counters are the named counters of a state's table, in a stable order.
func counters(s netstate.State) []string {
	names := []string{counterListenBypass, counterBlocked, counterExitDown}
	for _, d := range s.Classify.Decisions {
		names = append(names, d.Counter)
	}
	for _, r := range s.Guard.Rules {
		names = append(names, r.Counter)
	}
	return names
}

// renderDecide writes the chains that pick a connection's verdict. They are
// entered only for the first packet of a new, undecided connection.
func renderDecide(w *writer, c netstate.Classify) {
	direct := mark(netstate.MarkDirect)

	w.line(1, "chain decide_local {")
	w.line(2, "meta l4proto tcp th sport @%s %sct mark set %s return", setListenTCP, w.count(counterListenBypass), direct)
	w.line(2, "meta l4proto udp th sport @%s %sct mark set %s return", setListenUDP, w.count(counterListenBypass), direct)
	w.line(2, "jump decide")
	w.line(1, "}")

	w.line(1, "chain decide {")
	w.line(2, "meta mark & %s == %s ct mark set %s return", mark(netstate.BypassBit), mark(netstate.BypassBit), direct)
	w.line(2, "ip daddr @%s ct mark set %s return", setExempt4, direct)
	w.line(2, "ip6 daddr @%s ct mark set %s return", setExempt6, direct)
	for _, d := range c.Decisions {
		verdict := d.Verdict.Mark
		if c.Observe {
			// Observe counts the decision and changes nothing (ТЗ §8).
			verdict = netstate.MarkDirect
		}
		w.line(2, "%s daddr @%s %sct mark set %s return",
			addrKeyword(d.Family), SetName(d.Set), w.count(d.Counter), mark(verdict))
	}
	w.line(2, "ct mark set %s", direct)
	w.line(1, "}")
}

// renderClassify writes the base chains that classify connections.
func renderClassify(w *writer, c netstate.Classify) {
	restore := ""
	if len(c.Exits) > 0 {
		restore = fmt.Sprintf("ct direction original ct mark %s meta mark set ct mark", exitMarks(c.Exits))
	}

	w.line(1, "chain prerouting {")
	w.line(2, "type filter hook prerouting priority mangle; policy accept;")
	w.line(2, "iifname @%s return", setUplinks)
	w.line(2, "iifname @%s return", setExits)
	w.line(2, "ct state new ct mark 0 jump decide")
	w.lineIf(restore != "", 2, "%s", restore)
	w.line(1, "}")

	w.line(1, "chain output {")
	w.line(2, "type route hook output priority mangle; policy accept;")
	w.line(2, "ct state new ct mark 0 jump decide_local")
	rejectRules(w, "@"+setDeadExits, counterExitDown)
	w.lineIf(restore != "", 2, "%s", restore)
	w.line(1, "}")

	w.line(1, "chain reject_forward {")
	w.line(2, "type filter hook forward priority filter; policy accept;")
	rejectRules(w, mark(netstate.MarkBlock), counterBlocked)
	rejectRules(w, "@"+setDeadExits, counterExitDown)
	w.line(1, "}")

	w.line(1, "chain reject_output {")
	w.line(2, "type filter hook output priority filter; policy accept;")
	rejectRules(w, mark(netstate.MarkBlock), counterBlocked)
	w.line(1, "}")
}

// renderExits writes what traffic leaving through an exit needs.
func renderExits(w *writer) {
	// Exit tunnels have a smaller MTU than the uplink, and a local socket picked
	// its MSS before the mark rerouted it; clamping at postrouting covers both
	// forwarded and local connections.
	w.line(1, "chain clamp {")
	w.line(2, "type filter hook postrouting priority mangle; policy accept;")
	w.line(2, "oifname @%s tcp flags syn tcp option maxseg size set rt mtu", setExits)
	w.line(1, "}")

	// A rerouted local connection already has the node's address as source, and
	// forwarded traffic carries a downstream address: both need the exit's
	// address, or no reply comes back. The agent masquerades on its own and
	// relies on nobody else's NAT (ТЗ §3.3).
	w.line(1, "chain exit_snat {")
	w.line(2, "type nat hook postrouting priority srcnat; policy accept;")
	w.line(2, "oifname @%s masquerade", setExits)
	w.line(1, "}")
}

// dstnatPriority is the standard priority of destination NAT.
const dstnatPriority = -100

// renderDNS sends DNS to the resolver, so the addresses of listed domains reach
// its sets (ТЗ §5): the queries of downstream clients and of the host itself,
// except the resolver's own upstream queries. The redirect matches only while
// the health says the resolver is up. The resolver's port stays shut on the
// uplink: it must never become an open resolver.
func renderDNS(w *writer, c netstate.Classify) {
	redirect := fmt.Sprintf("meta l4proto { tcp, udp } th dport @%s redirect to :%d", setDNSPorts, c.DNSPort)

	w.line(1, "chain dns_redirect {")
	w.line(2, "type nat hook prerouting priority dstnat; policy accept;")
	w.line(2, "iifname @%s return", setUplinks)
	w.line(2, "iifname @%s return", setExits)
	w.line(2, "%s", redirect)
	w.line(1, "}")
	w.line(1, "chain dns_local {")
	// dstnat spelled as its number: nft before 1.0.3 (Ubuntu 22.04 has
	// 1.0.2) accepts the name for prerouting only.
	w.line(2, "type nat hook output priority %d; policy accept;", dstnatPriority)
	w.line(2, "meta skuid %d return", c.ResolverUID)
	w.line(2, "%s", redirect)
	w.line(1, "}")
	w.line(1, "chain dns_guard {")
	w.line(2, "type filter hook input priority filter; policy accept;")
	w.line(2, "iifname @%s meta l4proto { tcp, udp } th dport %d drop", setUplinks, c.DNSPort)
	w.line(1, "}")
}

// guardPriority places the guard after conntrack (-200), which its "new"
// test needs, and before classification (-150) and DNAT (-100): one chain
// covers the node's own sockets, containers behind DNAT and forwarding.
const guardPriority = -160

// guardLogLimit caps the guard's log per rule: a scan of the whole address
// space must not flood the kernel log.
const guardLogLimit = "limit rate 10/minute burst 20 packets"

// renderGuard writes the guard (guard ТЗ §4): new connections arriving from an
// uplink with a listed source are refused. Replies to connections the node
// opened are not new and pass (G-2); exempt sources pass (G-3); nothing that
// did not come in through an uplink is looked at (G-5).
func renderGuard(w *writer, g netstate.Guard) {
	w.line(1, "chain guard {")
	w.line(2, "type filter hook prerouting priority %d; policy accept;", guardPriority)
	w.line(2, "iifname != @%s return", setUplinks)
	w.line(2, "ct state != new return")
	w.line(2, "ip saddr @%s return", setExempt4)
	w.line(2, "ip6 saddr @%s return", setExempt6)
	rejects := false
	for _, r := range g.Rules {
		match := fmt.Sprintf("%s saddr @%s", addrKeyword(r.Family), SetName(r.Set))
		prefix := "vnm-guard"
		if g.Observe {
			prefix = "vnm-guard-observe"
		}
		w.lineIf(r.Log, 2, "%s %s log prefix \"%s %s: \"", match, guardLogLimit, prefix, r.List)
		verdict := "drop"
		switch {
		case g.Observe:
			// Observe counts the first match and refuses nothing.
			verdict = "return"
		case r.Reject:
			verdict, rejects = "jump "+chainGuardReject, true
		}
		w.line(2, "%s %s%s", match, w.count(r.Counter), verdict)
	}
	w.line(1, "}")
	if rejects {
		w.line(1, "chain %s {", chainGuardReject)
		w.line(2, "meta l4proto tcp reject with tcp reset")
		w.line(2, "reject with icmpx admin-prohibited")
		w.line(1, "}")
	}
}

const chainGuardReject = "guard_reject"

// SetName is the nft name of a planned set. List sets carry a prefix so that
// no list name can collide with the fixed sets.
func SetName(planned string) string { return listPrefix + planned }

// rejectRules rejects original-direction packets whose connection mark matches:
// TCP with a reset, everything else with an ICMP error, so the client fails at
// once instead of waiting for a timeout.
func rejectRules(w *writer, match, counter string) {
	w.line(2, "ct direction original ct mark %s %smeta l4proto tcp reject with tcp reset", match, w.count(counter))
	w.line(2, "ct direction original ct mark %s %sreject with icmpx admin-prohibited", match, w.count(counter))
}

// Features are what the kernel can do beyond the base the agent requires.
type Features struct {
	// NamedCounters means rules can reference named counters (nft_objref).
	// Stripped kernels (some hosting images) lack it: the rules then count nothing, and the
	// policy works all the same.
	NamedCounters bool
}

// AllFeatures is a stock kernel.
var AllFeatures = Features{NamedCounters: true}

// writer accumulates indented lines for a kernel with the given features.
type writer struct {
	strings.Builder
	f Features
}

// count is the statement that counts a rule's matches in the named counter,
// or nothing where rules cannot reference one.
func (w *writer) count(counter string) string {
	if !w.f.NamedCounters {
		return ""
	}
	return fmt.Sprintf("counter name %s ", counter)
}

func (w *writer) line(indent int, format string, args ...any) {
	w.WriteString(strings.Repeat("\t", indent))
	fmt.Fprintf(w, format, args...)
	w.WriteByte('\n')
}

func (w *writer) lineIf(cond bool, indent int, format string, args ...any) {
	if cond {
		w.line(indent, format, args...)
	}
}

// fill replaces the elements of a set of the applied table.
func (w *writer) fill(set string, elements []string) {
	w.line(0, "flush set %s %s %s", TableFamily, TableName, set)
	w.lineIf(len(elements) > 0, 0, "add element %s %s %s { %s }", TableFamily, TableName, set, strings.Join(elements, ", "))
}

// set writes a named set. nft rejects an empty element list, so an empty set is
// written without one.
func (w *writer) set(name, typ, flags string, elements []string) {
	w.line(1, "set %s {", name)
	w.line(2, "type %s;", typ)
	w.lineIf(flags != "", 2, "flags %s;", flags)
	if len(elements) > 0 {
		w.line(2, "elements = {")
		for i, e := range elements {
			sep := ","
			if i == len(elements)-1 {
				sep = ""
			}
			w.line(3, "%s%s", e, sep)
		}
		w.line(2, "}")
	}
	w.line(1, "}")
}

func mark(m uint32) string { return fmt.Sprintf("0x%08x", m) }

func exitMarks(exits []netstate.Exit) string {
	marks := make([]string, 0, len(exits))
	for _, e := range exits {
		marks = append(marks, mark(netstate.ExitMark(e.Slot)))
	}
	return "{ " + strings.Join(marks, ", ") + " }"
}

func exitIfaces(exits []netstate.Exit) []string {
	out := make([]string, 0, len(exits))
	for _, e := range exits {
		out = append(out, e.Iface)
	}
	return out
}

func addrType(f netstate.Family) string {
	if f == netstate.IPv6 {
		return "ipv6_addr"
	}
	return "ipv4_addr"
}

func addrKeyword(f netstate.Family) string {
	if f == netstate.IPv6 {
		return "ip6"
	}
	return "ip"
}

func quoted(names []string) []string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, fmt.Sprintf("%q", n))
	}
	return out
}

func prefixes(in []netip.Prefix) []string {
	out := make([]string, 0, len(in))
	for _, p := range in {
		out = append(out, p.String())
	}
	return out
}

func ports(in []uint16) []string {
	out := make([]string, 0, len(in))
	for _, p := range in {
		out = append(out, fmt.Sprint(p))
	}
	return out
}
