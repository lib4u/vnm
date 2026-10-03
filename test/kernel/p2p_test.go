package kernel

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/lib4u/vnm/internal/domain/policy"
	"github.com/lib4u/vnm/internal/infrastructure/nftables"
	"github.com/lib4u/vnm/internal/testsupport"
)

// The agent's runtime elements land in the kernel with their timeout, a
// refused peer takes the established flow down with it, and a replacement of
// the table keeps the peers and bans (p2p ТЗ §3.3–3.4).
func TestP2PRuntimeSets(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	in := testsupport.PlanInput()
	in.Policy.P2P = policy.P2P{Mode: policy.ModeEnforce, Signatures: policy.Signatures}
	state := testsupport.MustPlan(t, in)
	if err := r.applier.Apply(ctx, state); err != nil {
		t.Fatal(err)
	}

	var sets nftables.P2PSets
	peer := netip.MustParseAddr("203.0.113.77")
	client := netip.MustParseAddr("10.8.0.2")
	if err := sets.AddPeer(ctx, peer, 2*time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := sets.Ban(ctx, client, 3*time.Minute); err != nil {
		t.Fatal(err)
	}
	for set, addr := range map[string]string{"p2p_peers4": "203.0.113.77", "p2p_ban4": "10.8.0.2"} {
		out := r.sh(t, "nft list set inet vnm "+set)
		if !strings.Contains(out, addr+" timeout") && !strings.Contains(out, addr+" expires") {
			t.Fatalf("%s has no %s with a timeout:\n%s", set, addr, out)
		}
	}

	// A datagram to the refused peer, on a port nothing else refuses, never
	// leaves: the local send fails at once.
	r.sh(t, "ip link add p2p0 type dummy 2>/dev/null; ip link set p2p0 up; ip route replace 203.0.113.0/24 dev p2p0")
	before := r.counter(t, "p_peer")
	if out := r.sh(t, "(echo x > /dev/udp/203.0.113.77/6881) 2>/dev/null && echo sent || echo refused"); out != "refused" {
		t.Fatalf("a datagram to a refused peer went out: %s", out)
	}
	if after := r.counter(t, "p_peer"); after <= before {
		t.Fatalf("p_peer did not count: %d → %d", before, after)
	}
	if out := r.sh(t, "(echo x > /dev/udp/203.0.113.78/6881) 2>/dev/null && echo sent || echo refused"); out != "sent" {
		t.Fatalf("a datagram to another address was refused: %s", out)
	}

	// Any change that replaces the table keeps the runtime elements.
	next := state
	next.P2P.BanNonWeb = true
	if err := r.applier.Apply(ctx, next); err != nil {
		t.Fatal(err)
	}
	if out := r.sh(t, "nft list set inet vnm p2p_peers4"); !strings.Contains(out, "203.0.113.77") {
		t.Fatalf("the replace dropped the peer:\n%s", out)
	}
	if out := r.sh(t, "nft list set inet vnm p2p_ban4"); !strings.Contains(out, "10.8.0.2") {
		t.Fatalf("the replace dropped the ban:\n%s", out)
	}
}
