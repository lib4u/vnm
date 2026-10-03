package p2pwatch_test

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/lib4u/vnm/internal/domain/policy"
	"github.com/lib4u/vnm/internal/infrastructure/ndpid"
	"github.com/lib4u/vnm/internal/usecase/p2pwatch"
)

type fakeSets struct {
	peers []netip.Addr
	bans  []netip.Addr
	ttls  []time.Duration
}

func (f *fakeSets) AddPeer(_ context.Context, a netip.Addr, ttl time.Duration) error {
	f.peers = append(f.peers, a)
	f.ttls = append(f.ttls, ttl)
	return nil
}

func (f *fakeSets) Ban(_ context.Context, a netip.Addr, ttl time.Duration) error {
	f.bans = append(f.bans, a)
	return nil
}

type fakeListener struct{}

func (fakeListener) Serve(ctx context.Context, _ string, _ int, _ func(ndpid.Event)) error {
	<-ctx.Done()
	return nil
}
func (fakeListener) Connections() int64 { return 0 }

var node = netip.MustParseAddr("192.0.2.100")

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func setup(mode policy.Mode) (*p2pwatch.Watcher, *fakeSets, *clock) {
	sets := &fakeSets{}
	c := &clock{t: time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)}
	w := p2pwatch.New(p2pwatch.Deps{
		Sets: sets, Listener: fakeListener{},
		Local: func(a netip.Addr) bool { return a == node },
		Log:   slog.New(slog.NewTextHandler(io.Discard, nil)), Now: c.now,
	})
	w.Update(context.Background(), policy.P2P{
		Mode: mode, Signatures: policy.Signatures,
		NDPI: policy.NDPI{PeerTTL: 10 * time.Minute},
		Ban:  policy.Ban{Threshold: 5, Window: 5 * time.Minute, TTL: 30 * time.Minute},
	}, true)
	return w, sets, c
}

func bt(src, dst string) ndpid.Event {
	return ndpid.Event{Name: "detected", L4: "udp", Src: netip.MustParseAddr(src), Dst: netip.MustParseAddr(dst),
		Proto: "BitTorrent", DPI: true}
}

// A proxy's flow leaves from the node's address: its peer is refused, nobody
// is banned.
func TestEnforceRefusesPeerOnce(t *testing.T) {
	w, sets, c := setup(policy.ModeEnforce)
	ctx := context.Background()
	w.Handle(ctx, bt("192.0.2.100", "198.51.100.7"))
	w.Handle(ctx, bt("198.51.100.7", "192.0.2.100")) // the peer opened it: same peer
	if len(sets.peers) != 1 || sets.peers[0] != netip.MustParseAddr("198.51.100.7") || sets.ttls[0] != 10*time.Minute {
		t.Fatalf("peers = %v %v", sets.peers, sets.ttls)
	}
	c.t = c.t.Add(11 * time.Minute) // its refusal expired: refused again
	w.Handle(ctx, bt("192.0.2.100", "198.51.100.7"))
	if len(sets.peers) != 2 || len(sets.bans) != 0 {
		t.Fatalf("peers = %v, bans = %v", sets.peers, sets.bans)
	}
	if s := w.Stats(); s.Detections != 3 || s.Peers != 2 {
		t.Fatalf("stats = %+v", s)
	}
}

// Only packet inspection counts, and only BitTorrent; a verdict must be a
// detection.
func TestIgnoresGuessesAndOthers(t *testing.T) {
	w, sets, _ := setup(policy.ModeEnforce)
	ctx := context.Background()
	guess := bt("192.0.2.100", "198.51.100.7")
	guess.DPI = false
	other := bt("192.0.2.100", "198.51.100.8")
	other.Proto = "TLS.YouTube"
	idle := bt("192.0.2.100", "198.51.100.9")
	idle.Name = "idle"
	for _, e := range []ndpid.Event{guess, other, idle} {
		w.Handle(ctx, e)
	}
	if len(sets.peers) != 0 || w.Stats().Detections != 0 {
		t.Fatalf("acted on %v", sets.peers)
	}
}

// A tunnel client is banned once its flows reach the threshold of distinct
// peers within the window; repeats of one peer do not count.
func TestBansTunnelClientOnSwarm(t *testing.T) {
	w, sets, c := setup(policy.ModeEnforce)
	ctx := context.Background()
	for range 10 {
		w.Handle(ctx, bt("10.8.0.2", "198.51.100.1"))
	}
	if len(sets.bans) != 0 {
		t.Fatal("one peer banned the client")
	}
	for i := 2; i <= 5; i++ {
		c.t = c.t.Add(10 * time.Second)
		w.Handle(ctx, bt("10.8.0.2", netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}).String()))
	}
	if len(sets.bans) != 1 || sets.bans[0] != netip.MustParseAddr("10.8.0.2") {
		t.Fatalf("bans = %v", sets.bans)
	}
	// Banned: more peers do not ban again until the ban ends.
	w.Handle(ctx, bt("10.8.0.2", "198.51.100.66"))
	if len(sets.bans) != 1 {
		t.Fatalf("banned twice: %v", sets.bans)
	}
}

// Peers spread over more than the window never make a swarm.
func TestSwarmWindowSlides(t *testing.T) {
	w, sets, c := setup(policy.ModeEnforce)
	ctx := context.Background()
	for i := 1; i <= 8; i++ {
		c.t = c.t.Add(2 * time.Minute)
		w.Handle(ctx, bt("10.8.0.3", netip.AddrFrom4([4]byte{203, 0, 113, byte(i)}).String()))
	}
	if len(sets.bans) != 0 {
		t.Fatalf("a slow trickle banned the client: %v", sets.bans)
	}
}

// Observe decides the same and touches nothing.
func TestObserveTouchesNothing(t *testing.T) {
	w, sets, _ := setup(policy.ModeObserve)
	ctx := context.Background()
	for i := 1; i <= 6; i++ {
		w.Handle(ctx, bt("10.8.0.4", netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}).String()))
	}
	if len(sets.peers) != 0 || len(sets.bans) != 0 {
		t.Fatalf("observe acted: peers %v bans %v", sets.peers, sets.bans)
	}
	if s := w.Stats(); s.Peers != 6 || s.Bans != 1 {
		t.Fatalf("stats = %+v", s)
	}
}

// Until the kernel holds the p2p part, there is nothing to add elements to.
func TestNothingBeforeApplied(t *testing.T) {
	w, sets, _ := setup(policy.ModeEnforce)
	w.Update(context.Background(), policy.P2P{Mode: policy.ModeEnforce, Signatures: policy.Signatures}, false)
	w.Handle(context.Background(), bt("192.0.2.100", "198.51.100.7"))
	if len(sets.peers) != 0 {
		t.Fatal("acted before the kernel held the part")
	}
}

// A flow with no public side — two private addresses — names no peer.
func TestNoPublicSide(t *testing.T) {
	w, sets, _ := setup(policy.ModeEnforce)
	w.Handle(context.Background(), bt("10.8.0.2", "192.168.1.5"))
	if len(sets.peers) != 0 || w.Stats().Detections != 0 {
		t.Fatalf("peers = %v", sets.peers)
	}
}
