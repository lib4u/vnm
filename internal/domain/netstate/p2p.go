package netstate

// P2P is the peer-to-peer part of the state (p2p ТЗ §4): packets matching a
// BitTorrent signature never leave through an uplink, whether a process of the
// node sent them or a tunnel client did. Exempt destinations, the web ports
// and DNS are never touched.
type P2P struct {
	// Observe counts what enforce would refuse and refuses nothing.
	Observe bool
	// Signatures are tried in order.
	Signatures []P2PSignature
	// BanNonWeb leaves a banned tunnel client DNS and the web ports;
	// otherwise a ban takes everything (p2p ТЗ §3.4). The peers and bans
	// themselves are runtime elements the agent adds with a timeout.
	BanNonWeb bool
}

// P2PSignature is one signature the kernel refuses.
type P2PSignature struct {
	// Name is the signature's configuration spelling.
	Name string
	// Counter names the counter that records the refused packets.
	Counter string
}

// Active reports whether the part has anything to apply.
func (p P2P) Active() bool { return len(p.Signatures) > 0 }
