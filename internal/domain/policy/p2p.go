package policy

import (
	"strings"
	"time"
)

// P2P is the peer-to-peer part of the policy (p2p ТЗ): a node must carry no
// BitTorrent download or upload, whichever tunnel the client came in by. Like
// the guard, it is independent of the egress mode.
type P2P struct {
	// Mode is ModeOff unless the file sets it: the part is never switched on
	// by default.
	Mode Mode
	// Signatures are the packet signatures the kernel refuses (p2p ТЗ §3.1).
	Signatures []Signature
	// NDPI is the flow classifier (p2p ТЗ §3.3).
	NDPI NDPI
	// Ban is what happens to a tunnel client that keeps torrenting (§3.4).
	Ban Ban
}

// NDPI configures the use of nDPId's verdicts.
type NDPI struct {
	Enabled bool
	// Socket is the UNIX socket the agent listens on and nDPId writes to.
	Socket string
	// PeerTTL is how long a peer of a detected BitTorrent flow stays refused.
	PeerTTL time.Duration
}

// Ban configures the refusal of a tunnel client that keeps torrenting.
type Ban struct {
	// Threshold signals within Window ban the client for TTL.
	Threshold int
	Window    time.Duration
	TTL       time.Duration
	// NonWeb leaves a banned client DNS and the web ports; otherwise it loses
	// everything.
	NonWeb bool
}

// Defaults of the classifier and the ban (p2p ТЗ §2).
const (
	// DefaultNDPISocket sits in a directory of its own: the agent's runtime
	// directory is closed to everyone, nDPId's user included.
	DefaultNDPISocket   = "/run/vnm-p2p/ndpid.sock"
	DefaultPeerTTL      = 10 * time.Minute
	DefaultBanThreshold = 20
	DefaultBanWindow    = 5 * time.Minute
	DefaultBanTTL       = 30 * time.Minute
)

// Signature is a strict match on the fields of a BitTorrent packet.
type Signature uint8

const (
	SignatureUnknown Signature = iota
	// SignatureUTPSyn is the ST_SYN that opens a uTP connection (BEP 29). Its
	// header stays readable when the payload is encrypted, so refusing it
	// keeps an encrypted uTP peer connection from ever opening.
	SignatureUTPSyn
	// SignatureDHT is a KRPC query or response of the DHT (BEP 5).
	SignatureDHT
	// SignatureUDPTracker is the connect request of the UDP tracker
	// protocol (BEP 15).
	SignatureUDPTracker
	// SignatureBTHandshake is the plaintext handshake of a TCP peer
	// connection.
	SignatureBTHandshake
)

// Signatures lists every signature in its configuration spelling, in the
// order the kernel tries them.
var Signatures = []Signature{SignatureUTPSyn, SignatureDHT, SignatureUDPTracker, SignatureBTHandshake}

var signatureNames = map[Signature]string{
	SignatureUTPSyn:      "utp_syn",
	SignatureDHT:         "dht",
	SignatureUDPTracker:  "udp_tracker",
	SignatureBTHandshake: "bt_handshake",
}

func (s Signature) String() string {
	if name, ok := signatureNames[s]; ok {
		return name
	}
	return "unknown"
}

// ParseSignature returns the signature with the given configuration name.
func ParseSignature(name string) (Signature, bool) {
	for s, n := range signatureNames {
		if n == name {
			return s, true
		}
	}
	return SignatureUnknown, false
}

// Active reports whether the part is applied, counting only or not.
func (p P2P) Active() bool {
	return (p.Mode == ModeObserve || p.Mode == ModeEnforce) && len(p.Signatures) > 0
}

func (c Config) validateP2P(p *problems) {
	if len(c.P2P.Signatures) > 0 && c.P2P.Mode == ModeUnknown {
		p.add("p2p: mode is not set")
	}
	seen := map[Signature]bool{}
	for i, s := range c.P2P.Signatures {
		if s == SignatureUnknown {
			p.add("p2p signature %d is not one of %v", i, Signatures)
			continue
		}
		if seen[s] {
			p.add("p2p: signature %s is named more than once", s)
		}
		seen[s] = true
	}
	if n := c.P2P.NDPI; n.Enabled {
		if !strings.HasPrefix(n.Socket, "/") {
			p.add("p2p ndpi socket %q is not an absolute path", n.Socket)
		}
		if n.PeerTTL < time.Minute {
			p.add("p2p ndpi peer_ttl %v is under a minute", n.PeerTTL)
		}
	}
	if b := c.P2P.Ban; b.Threshold != 0 || b.Window != 0 || b.TTL != 0 {
		if b.Threshold < 5 {
			p.add("p2p ban threshold %d is under 5: a single signal must not ban a client", b.Threshold)
		}
		if b.Window < time.Minute || b.TTL < time.Minute {
			p.add("p2p ban window and ttl must be a minute or more")
		}
	}
}
