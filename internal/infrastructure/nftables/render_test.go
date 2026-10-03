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
