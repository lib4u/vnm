package nftables_test

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lib4u/vnm/internal/domain/netstate"
	"github.com/lib4u/vnm/internal/domain/policy"
	"github.com/lib4u/vnm/internal/infrastructure/nftables"
	"github.com/lib4u/vnm/internal/testsupport"
)

var update = flag.Bool("update", false, "rewrite golden files")

func planned(t *testing.T, mode policy.Mode) netstate.State {
	t.Helper()
	return plannedWith(t, func(cfg *policy.Config) {
		cfg.Mode = mode
		cfg.Guard.Mode = mode
		cfg.P2P = policy.P2P{Mode: mode, Signatures: policy.Signatures}
	})
}

func plannedWith(t *testing.T, mutate func(*policy.Config)) netstate.State {
	t.Helper()
	in := testsupport.PlanInput()
	mutate(&in.Policy)
	in.Listen = netstate.Ports{TCP: []uint16{22, 443}, UDP: []uint16{8851}}
	return testsupport.MustPlan(t, in)
}

// guardOnly is a node whose egress is off: the table holds the guard alone.
func guardOnly(cfg *policy.Config) {
	cfg.Mode = policy.ModeOff
	cfg.Guard.Rules[0].Action = policy.GuardReject
	cfg.Guard.Rules[0].Log = false
}

// p2pOnly is a node whose egress and guard are off: the table holds the p2p
// part alone.
func p2pOnly(cfg *policy.Config) {
	cfg.Mode = policy.ModeOff
	cfg.Guard.Mode = policy.ModeOff
	cfg.P2P = policy.P2P{Mode: policy.ModeEnforce, Signatures: policy.Signatures}
}

// The golden files are the reviewable form of the ruleset: any change to what
// the agent writes into the kernel shows up as a diff of them.
func TestRenderGolden(t *testing.T) {
	states := map[string]netstate.State{
		"enforce":    planned(t, policy.ModeEnforce),
		"observe":    planned(t, policy.ModeObserve),
		"guard-only": plannedWith(t, guardOnly),
		"p2p-only":   plannedWith(t, p2pOnly),
	}
	for name, state := range states {
		t.Run(name, func(t *testing.T) {
			got := nftables.Render(state)
			path := filepath.Join("testdata", name+".nft")
			if *update {
				if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read golden (run with -update to create): %v", err)
			}
			if got != string(want) {
				t.Fatalf("ruleset differs from %s (run with -update after review)\n%s", path, got)
			}
		})
	}
}

// Two independently planned equal states must render byte-identically, or the
// agent would see drift where there is none.
func TestRenderIsDeterministic(t *testing.T) {
	first := nftables.Render(planned(t, policy.ModeEnforce))
	second := nftables.Render(planned(t, policy.ModeEnforce))
	if first != second {
		t.Fatal("two renders of equal states differ")
	}
}

// Observe must not be able to change traffic: no decision may record an exit
// or a block, and the guard refuses nothing.
func TestRenderObserveDecidesOnlyDirect(t *testing.T) {
	out := nftables.Render(planned(t, policy.ModeObserve))
	for line := range strings.SplitSeq(out, "\n") {
		switch {
		case strings.Contains(line, "counter name r0_") && !strings.HasSuffix(line, "ct mark set 0x0000ca6a return"):
			t.Errorf("observe decision is not direct: %s", strings.TrimSpace(line))
		case strings.Contains(line, "counter name g_") && !strings.HasSuffix(line, " return"):
			t.Errorf("observe guard refuses: %s", strings.TrimSpace(line))
		case strings.Contains(line, "counter name p_") && !strings.HasSuffix(line, " return"):
			t.Errorf("observe p2p refuses: %s", strings.TrimSpace(line))
		}
	}
}

// DNS goes to the resolver only through the health set, in both chains, in
// every mode: a dead resolver must not take the node's DNS down with it.
func TestRenderDNSRedirect(t *testing.T) {
	const want = "meta l4proto { tcp, udp } th dport @dns_ports redirect to :5353"
	for _, mode := range []policy.Mode{policy.ModeEnforce, policy.ModeObserve} {
		out := nftables.Render(planned(t, mode))
		if n := strings.Count(out, " redirect to "); n != 2 || strings.Count(out, want) != 2 {
			t.Errorf("%s: want 2 redirects %q (transit and host):\n%s", mode, want, out)
		}
	}
}

// While the health says the resolver is down, enforce sends IPv4 no decision
// matched through the failover exit — after every decision, before the
// direct default, DNS excepted; observe fails nothing over.
func TestRenderFailover(t *testing.T) {
	out := nftables.Render(planned(t, policy.ModeEnforce))
	decide := out[strings.Index(out, "chain decide {"):]
	decide = decide[:strings.Index(decide, "\n\t}")]
	lines := strings.Split(strings.TrimSpace(decide), "\n")
	n := len(lines)
	for i, want := range []string{
		"meta nfproto @failover meta l4proto { tcp, udp } th dport 53 ct mark set 0x0000ca6a return",
		"meta nfproto @failover counter name resolver_failover ct mark set 0x0000ca6c return",
		"ct mark set 0x0000ca6a",
	} {
		if got := strings.TrimSpace(lines[n-3+i]); got != want {
			t.Errorf("decide line %d from the end = %q, want %q", 3-i, got, want)
		}
	}
	if out := nftables.Render(planned(t, policy.ModeObserve)); strings.Contains(out, "@failover") {
		t.Errorf("observe fails over:\n%s", out)
	}
	for _, health := range []struct {
		h    netstate.Health
		want string
	}{
		{netstate.Health{}, "add element inet vnm failover { ipv4 }"},
		{netstate.Health{ResolverUp: true}, "add element inet vnm dns_ports { 53 }"},
	} {
		if got := nftables.HealthScript(health.h); !strings.Contains(got, health.want) || !strings.Contains(got, "flush set inet vnm failover") {
			t.Errorf("health %+v:\n%s", health.h, got)
		}
	}
}

// Enforce restores the packet mark only from an exit conntrack mark. A direct
// verdict records 0xca6a on the connection and does not write the packet mark,
// so a mark the cascade already set survives. Slot 0 still restores 0xca6c.
func TestRenderRestoresExitMarkOnly(t *testing.T) {
	out := nftables.Render(planned(t, policy.ModeEnforce))
	const (
		direct  = "0x0000ca6a"
		exit0   = "0x0000ca6c"
		restore = "meta mark set ct mark"
	)
	restores := 0
	for line := range strings.SplitSeq(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "meta mark set") {
			continue
		}
		restores++
		if !strings.Contains(line, restore) || !strings.Contains(line, "ct mark {") || strings.Contains(line, direct) || !strings.Contains(line, exit0) {
			t.Errorf("packet mark write is not a restore of the slot 0 exit mark: %s", line)
		}
	}
	if restores == 0 {
		t.Fatal("enforce ruleset does not restore the packet mark")
	}
	for line := range strings.SplitSeq(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "ct mark set "+direct) && strings.Contains(line, "meta mark set") {
			t.Errorf("direct decision sets the packet mark: %s", line)
		}
	}
}

// A table that only guards, or only refuses BitTorrent, classifies nothing: no
// chain may touch a connection's mark.
func TestRenderGuardOnlyLeavesMarksAlone(t *testing.T) {
	for name, mutate := range map[string]func(*policy.Config){"guard-only": guardOnly, "p2p-only": p2pOnly} {
		out := nftables.Render(plannedWith(t, mutate))
		for _, forbidden := range []string{"ct mark set", "meta mark set", "masquerade", "redirect"} {
			if strings.Contains(out, forbidden) {
				t.Errorf("%s table has %q:\n%s", name, forbidden, out)
			}
		}
	}
}

// Every signature the policy names becomes at least one refusing rule, and a
// signature it leaves out none.
func TestRenderP2PSignatures(t *testing.T) {
	out := nftables.Render(plannedWith(t, func(cfg *policy.Config) {
		p2pOnly(cfg)
		cfg.P2P.Signatures = []policy.Signature{policy.SignatureUTPSyn, policy.SignatureUDPTracker}
	}))
	for _, want := range []string{"counter name p_utp_syn drop", "counter name p_udp_tracker drop"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
	for _, absent := range []string{"p_dht", "p_bt_handshake"} {
		if strings.Contains(out, absent) {
			t.Errorf("signature not asked for is rendered: %s", absent)
		}
	}
}

// The ruleset must be accepted by the real kernel on a node without the
// table; replacing an existing one is the kernel tests' business
// (test/kernel), since it depends on what the table holds.
func TestScriptLoadsIntoKernel(t *testing.T) {
	testsupport.RequireNetns(t)
	path := filepath.Join(t.TempDir(), "vnm.nft")
	for _, state := range []netstate.State{planned(t, policy.ModeEnforce), planned(t, policy.ModeObserve), plannedWith(t, guardOnly), plannedWith(t, p2pOnly)} {
		state.Health = netstate.Health{DeadSlots: []int{0}, ResolverUp: true}
		if err := os.WriteFile(path, []byte(nftables.Script(state)), 0o644); err != nil {
			t.Fatal(err)
		}
		out, err := testsupport.InNetns(t, "nft -f "+path+" && nft list table inet vnm >/dev/null")
		if err != nil {
			t.Fatalf("nft rejected the ruleset: %v\n%s", err, out)
		}
	}
}
