package nftables

import "github.com/lib4u/vnm/internal/domain/netstate"

// p2pPriority places the p2p part after conntrack (-200), whose direction it
// tests, and the guard (-160), and before classification (-150): a refused
// packet never takes an exit (p2p ТЗ §4).
const p2pPriority = -155

const (
	chainP2P       = "p2p"
	chainP2PIn     = "p2p_in"
	chainP2PBanned = "p2p_banned"

	// The runtime sets (p2p ТЗ §3.3–3.4): the agent adds peers of detected
	// BitTorrent flows and banned tunnel clients, each with a timeout, and a
	// replacement of the table keeps them.
	setP2PPeers4 = "p2p_peers4"
	setP2PPeers6 = "p2p_peers6"
	setP2PBan4   = "p2p_ban4"
	setP2PBan6   = "p2p_ban6"

	counterP2PPeer = "p_peer"
	counterP2PBan  = "p_ban"
)

// p2pSetShapes are the runtime sets with what a replacement keeps them by.
var p2pSetShapes = map[string]setShape{
	setP2PPeers4: {typ: "ipv4_addr", timeout: true},
	setP2PPeers6: {typ: "ipv6_addr", timeout: true},
	setP2PBan4:   {typ: "ipv4_addr", timeout: true},
	setP2PBan6:   {typ: "ipv6_addr", timeout: true},
}

func renderP2PSets(w *writer) {
	for _, name := range []string{setP2PPeers4, setP2PPeers6, setP2PBan4, setP2PBan6} {
		w.set(name, p2pSetShapes[name].typ, "timeout", nil)
	}
}

// p2pSignatures are the strict matches of each signature (p2p ТЗ §3.1),
// offsets counted from the transport header. A UDP header is 8 bytes, so a
// UDP payload starts at @th,64; a TCP payload starts after the header length
// in doff, so the TCP handshake is matched for the two lengths clients send:
// 20 bytes plain and 32 with timestamps.
var p2pSignatures = map[string][]string{
	// ST_SYN v1 (type 4, version 1), no extension, timestamp_difference 0
	// and nothing but the 20-byte header (BEP 29). The first byte alone,
	// 0x41, is also a TURN ChannelData channel number; the fields together
	// are not.
	"utp_syn": {"udp length 28 @th,64,8 0x41 @th,72,8 0x00 @th,128,32 0x00000000"},
	// KRPC query and response (BEP 5): bencode keys are sorted, so a query
	// opens with its "a" dictionary and a response with "r", each with the
	// 20-byte node id first.
	"dht": {
		"meta l4proto udp @th,64,96 0x64313a6164323a696432303a", // d1:ad2:id20:
		"meta l4proto udp @th,64,96 0x64313a7264323a696432303a", // d1:rd2:id20:
	},
	// Connect request (BEP 15): the 64-bit protocol id, action 0, a
	// transaction id — 16 bytes, nothing else.
	"udp_tracker": {"udp length 24 @th,64,64 0x0000041727101980 @th,128,32 0x00000000"},
	// The plaintext handshake: 19, then "BitTorrent protocol" (first 16 bytes).
	"bt_handshake": {
		"tcp doff 5 @th,160,128 0x13426974546f7272656e742070726f74",
		"tcp doff 8 @th,256,128 0x13426974546f7272656e742070726f74",
	},
}

// renderP2P writes the p2p part (p2p ТЗ §4). Two base chains feed one: the
// node's own processes — a proxy's outbound connections — and tunnel clients,
// whatever came in through an uplink or an exit left aside. Only the
// original direction is looked at, so a reply to a client is never refused;
// exempt destinations, DNS and the web ports pass untouched (P-4).
func renderP2P(w *writer, p netstate.P2P) {
	w.line(1, "chain p2p_local {")
	w.line(2, "type filter hook output priority %d; policy accept;", p2pPriority)
	w.line(2, "oifname \"lo\" return")
	w.line(2, "jump %s", chainP2P)
	w.line(1, "}")

	w.line(1, "chain p2p_tunnel {")
	w.line(2, "type filter hook prerouting priority %d; policy accept;", p2pPriority)
	w.line(2, "iifname @%s jump %s", setUplinks, chainP2PIn)
	w.line(2, "iifname @%s return", setUplinks)
	w.line(2, "iifname @%s return", setExits)
	w.line(2, "fib daddr type local return")
	w.line(2, "ip saddr @%s jump %s", setP2PBan4, chainP2PBanned)
	w.line(2, "ip6 saddr @%s jump %s", setP2PBan6, chainP2PBanned)
	w.line(2, "jump %s", chainP2P)
	w.line(1, "}")

	verdict := "drop"
	if p.Observe {
		// Observe counts the match and refuses nothing.
		verdict = "return"
	}

	// From the internet (§3.1): a proxy's UDP is full-cone, so a swarm's peers
	// reach the client through the node on their own — an incoming uTP SYN or
	// DHT query to the node, and anything from a refused peer, never gets
	// through. The node's own services, on DNS and the web ports, are not
	// looked at; replies to what the node opened are not new.
	w.line(1, "chain %s {", chainP2PIn)
	w.line(2, "ct direction reply return")
	w.line(2, "ip saddr @%s return", setExempt4)
	w.line(2, "ip6 saddr @%s return", setExempt6)
	w.line(2, "udp dport { 53, 443 } return")
	w.line(2, "tcp dport { 53, 80, 443 } return")
	w.line(2, "ip saddr @%s %s%s", setP2PPeers4, w.count(counterP2PPeer), verdict)
	w.line(2, "ip6 saddr @%s %s%s", setP2PPeers6, w.count(counterP2PPeer), verdict)
	for _, s := range p.Signatures {
		for _, match := range p2pSignatures[s.Name] {
			w.line(2, "%s %s%s", match, w.count(s.Counter), verdict)
		}
	}
	w.line(1, "}")

	// A banned tunnel client (§3.4): everything, or all but DNS and the web.
	w.line(1, "chain %s {", chainP2PBanned)
	w.lineIf(p.BanNonWeb, 2, "udp dport { 53, 443 } return")
	w.lineIf(p.BanNonWeb, 2, "tcp dport { 53, 80, 443 } return")
	w.line(2, "%s%s", w.count(counterP2PBan), verdict)
	w.line(1, "}")

	w.line(1, "chain %s {", chainP2P)
	w.line(2, "ct direction reply return")
	w.line(2, "ip daddr @%s return", setExempt4)
	w.line(2, "ip6 daddr @%s return", setExempt6)
	w.line(2, "udp dport { 53, 443 } return")
	w.line(2, "tcp dport { 53, 80, 443 } return")
	// A peer of a flow nDPI found BitTorrent (§3.3): every packet to it,
	// established flows included, so the flow dies with the verdict.
	w.line(2, "ip daddr @%s %s%s", setP2PPeers4, w.count(counterP2PPeer), verdict)
	w.line(2, "ip6 daddr @%s %s%s", setP2PPeers6, w.count(counterP2PPeer), verdict)
	for _, s := range p.Signatures {
		for _, match := range p2pSignatures[s.Name] {
			w.line(2, "%s %s%s", match, w.count(s.Counter), verdict)
		}
	}
	w.line(1, "}")
}
