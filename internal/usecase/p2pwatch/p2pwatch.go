// Package p2pwatch acts on nDPI's BitTorrent verdicts (p2p ТЗ §3.3–3.4).
//
// nDPId sees a flow on an interface and says what it carries. When packet
// inspection — not a port or an address guess — finds BitTorrent, the
// watcher refuses the flow's peer for a while: the kernel then drops every
// packet to it, the flow in progress included. A tunnel client whose flows
// reach many distinct peers within a window is banned for a while. In
// observe, the same decisions are only counted.
//
// The watcher knows nothing of the services behind the flows: a proxy's
// flows leave from the node's own address and are refused by peer only;
// tunnel clients are told by their private address (P-7).
package p2pwatch

import (
	"context"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/lib4u/vnm/internal/domain/policy"
	"github.com/lib4u/vnm/internal/infrastructure/ndpid"
)

// Sets adds the runtime elements of the p2p part to the kernel.
type Sets interface {
	AddPeer(ctx context.Context, addr netip.Addr, ttl time.Duration) error
	Ban(ctx context.Context, addr netip.Addr, ttl time.Duration) error
}

// Listener serves nDPId's connections.
type Listener interface {
	Serve(ctx context.Context, path string, gid int, handle func(ndpid.Event)) error
	Connections() int64
}

// Deps are the watcher's collaborators.
type Deps struct {
	Sets     Sets
	Listener Listener
	// Local reports whether an address is one of the node's own.
	Local func(netip.Addr) bool
	// GID is the group nDPId runs as, which may write to the socket.
	GID int
	Log *slog.Logger
	Now func() time.Time
}

// Stats are what the watcher did since it started.
type Stats struct {
	// Detections are BitTorrent verdicts of packet inspection.
	Detections uint64
	// Peers and Bans are the peers refused and the tunnel clients banned —
	// in observe, the ones that would have been.
	Peers uint64
	Bans  uint64
	// Connected means nDPId is writing to the socket.
	Connected bool
}

// Watcher turns verdicts into refusals.
type Watcher struct {
	d Deps

	mu      sync.Mutex
	pol     policy.P2P
	applied bool
	serving string
	stop    context.CancelFunc
	peers   map[netip.Addr]time.Time
	banned  map[netip.Addr]time.Time
	swarm   map[netip.Addr]map[netip.Addr]time.Time
	stats   Stats
}

// New returns a watcher that listens for nothing until Update enables it.
func New(d Deps) *Watcher {
	return &Watcher{
		d:      d,
		peers:  map[netip.Addr]time.Time{},
		banned: map[netip.Addr]time.Time{},
		swarm:  map[netip.Addr]map[netip.Addr]time.Time{},
	}
}

// Update gives the watcher the policy's p2p part and whether the kernel holds
// it: verdicts are acted on only then. The listener follows the policy: it
// starts, moves to another socket or stops.
func (w *Watcher) Update(ctx context.Context, p policy.P2P, applied bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.pol, w.applied = p, applied
	want := ""
	if p.Active() && p.NDPI.Enabled {
		want = p.NDPI.Socket
	}
	if want == w.serving {
		return
	}
	if w.stop != nil {
		w.stop()
		w.stop = nil
	}
	w.serving = want
	if want == "" {
		return
	}
	lctx, cancel := context.WithCancel(ctx)
	w.stop = cancel
	go func() {
		if err := w.d.Listener.Serve(lctx, want, w.d.GID, func(e ndpid.Event) { w.Handle(lctx, e) }); err != nil {
			w.d.Log.Error("ndpid listener", "socket", want, "error", err)
		}
	}()
}

// Stats returns what the watcher did so far.
func (w *Watcher) Stats() Stats {
	w.mu.Lock()
	defer w.mu.Unlock()
	s := w.stats
	s.Connected = w.serving != "" && w.d.Listener.Connections() > 0
	return s
}

// Handle acts on one event of nDPId.
func (w *Watcher) Handle(ctx context.Context, e ndpid.Event) {
	if !e.Verdict() || !e.BitTorrent() || !e.DPI {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.applied || !w.pol.Active() {
		return
	}
	peer, client := w.sides(e)
	if !peer.IsValid() {
		return
	}
	w.stats.Detections++
	now := w.d.Now()
	enforce := w.pol.Mode == policy.ModeEnforce

	if until, ok := w.peers[peer]; !ok || !now.Before(until) {
		w.peers[peer] = now.Add(w.pol.NDPI.PeerTTL)
		w.stats.Peers++
		if enforce {
			if err := w.d.Sets.AddPeer(ctx, peer, w.pol.NDPI.PeerTTL); err != nil {
				w.d.Log.Warn("refuse peer", "peer", peer, "error", err)
			}
		}
		w.d.Log.Info("p2p peer", "peer", peer, "proto", e.Proto, "client", client, "enforce", enforce)
	}
	if client.IsValid() {
		w.count(ctx, client, peer, now, enforce)
	}
	w.prune(now)
}

// count adds the peer to the client's swarm and bans the client when the
// swarm reaches the threshold (§3.4).
func (w *Watcher) count(ctx context.Context, client, peer netip.Addr, now time.Time, enforce bool) {
	b := w.pol.Ban
	if until, ok := w.banned[client]; ok && now.Before(until) {
		return
	}
	peers := w.swarm[client]
	if peers == nil {
		peers = map[netip.Addr]time.Time{}
		w.swarm[client] = peers
	}
	peers[peer] = now
	for p, seen := range peers {
		if now.Sub(seen) > b.Window {
			delete(peers, p)
		}
	}
	if len(peers) < b.Threshold {
		return
	}
	delete(w.swarm, client)
	w.banned[client] = now.Add(b.TTL)
	w.stats.Bans++
	if enforce {
		if err := w.d.Sets.Ban(ctx, client, b.TTL); err != nil {
			w.d.Log.Warn("ban client", "client", client, "error", err)
		}
	}
	w.d.Log.Warn("p2p ban", "client", client, "peers", b.Threshold, "window", b.Window, "ttl", b.TTL, "enforce", enforce)
}

// sides tells the flow's peer — the public address that is not the node's —
// from its tunnel client, a private address, if the flow was seen before NAT.
func (w *Watcher) sides(e ndpid.Event) (peer, client netip.Addr) {
	for _, a := range []netip.Addr{e.Src, e.Dst} {
		switch {
		case tunnelSide(a):
			client = a
		case public(a) && !w.d.Local(a) && !peer.IsValid():
			peer = a
		}
	}
	return peer, client
}

// cgnat is the shared address space tunnels hand out besides RFC 1918.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

func tunnelSide(a netip.Addr) bool { return a.IsPrivate() || cgnat.Contains(a) }

func public(a netip.Addr) bool {
	return a.IsGlobalUnicast() && !a.IsPrivate() && !cgnat.Contains(a)
}

// maxTracked bounds the watcher's memory: past it, expired entries go.
const maxTracked = 10000

func (w *Watcher) prune(now time.Time) {
	if len(w.peers) > maxTracked {
		for a, until := range w.peers {
			if !now.Before(until) {
				delete(w.peers, a)
			}
		}
	}
	if len(w.banned) > maxTracked {
		for a, until := range w.banned {
			if !now.Before(until) {
				delete(w.banned, a)
			}
		}
	}
	if len(w.swarm) > maxTracked {
		for c, peers := range w.swarm {
			for p, seen := range peers {
				if now.Sub(seen) > w.pol.Ban.Window {
					delete(peers, p)
				}
			}
			if len(peers) == 0 {
				delete(w.swarm, c)
			}
		}
	}
}
