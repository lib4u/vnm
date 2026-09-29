// Package kernel runs the applier against a real kernel: the nft and ip
// adapters, the state file and the apply order together, inside a throwaway
// network namespace (see testsupport.MainInNetns).
package kernel

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lib4u/vnm/internal/domain/netstate"
	"github.com/lib4u/vnm/internal/domain/policy"
	"github.com/lib4u/vnm/internal/infrastructure/iproute"
	"github.com/lib4u/vnm/internal/infrastructure/nftables"
	"github.com/lib4u/vnm/internal/infrastructure/runner"
	"github.com/lib4u/vnm/internal/infrastructure/statefile"
	"github.com/lib4u/vnm/internal/testsupport"
	"github.com/lib4u/vnm/internal/usecase/apply"
)

func TestMain(m *testing.M) {
	os.Exit(testsupport.MainInNetns(m))
}

type rig struct {
	fw      *nftables.Firewall
	rt      *iproute.Router
	store   *statefile.Store
	applier *apply.Applier
}

func newRig(t *testing.T) rig {
	t.Helper()
	testsupport.RequireInNetns(t)
	run := runner.System{Timeout: 10 * time.Second}
	r := rig{
		fw:    nftables.NewFirewall(run),
		rt:    iproute.NewRouter(run),
		store: statefile.New(t.TempDir()),
	}
	r.applier = apply.New(r.fw, r.rt, r.store)

	// Every test starts from a clean namespace state: the namespace is shared
	// by all tests of the binary.
	r.sh(t, "ip link del warp 2>/dev/null || true")
	r.sh(t, "ip link add warp type dummy && ip link set warp up")
	if err := r.applier.Apply(context.Background(), netstate.State{}); err != nil {
		t.Fatalf("reset: %v", err)
	}
	return r
}

func (r rig) sh(t *testing.T, script string) string {
	t.Helper()
	out, err := testsupport.Shell(script)
	if err != nil {
		t.Fatalf("%s: %v\n%s", script, err, out)
	}
	return out
}

func desired(t *testing.T) netstate.State {
	t.Helper()
	return testsupport.MustPlan(t, testsupport.PlanInput())
}

func (r rig) requireApplied(t *testing.T, want netstate.State) {
	t.Helper()
	ctx := context.Background()
	rules, err := r.rt.Rules(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(rules, want.Rules) {
		t.Errorf("rules = %+v, want %+v", rules, want.Rules)
	}
	routes, err := r.rt.Routes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(routes, want.Routes) {
		t.Errorf("routes = %+v, want %+v", routes, want.Routes)
	}
	present, err := r.fw.Present(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if present == want.Empty() {
		t.Errorf("table present = %t for empty=%t", present, want.Empty())
	}
}

func TestApplyAndReapply(t *testing.T) {
	r := newRig(t)
	want := desired(t)
	for range 2 {
		if err := r.applier.Apply(context.Background(), want); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		r.requireApplied(t, want)
	}
}

func TestOffRemovesEverythingOwned(t *testing.T) {
	r := newRig(t)
	if err := r.applier.Apply(context.Background(), desired(t)); err != nil {
		t.Fatal(err)
	}
	if err := r.applier.Apply(context.Background(), netstate.State{}); err != nil {
		t.Fatalf("Apply off: %v", err)
	}
	r.requireApplied(t, netstate.State{})
}

// A rule someone left in the owned range — like the hand-made WARP rules on
// hand-made WARP setups — is removed, including one the domain cannot express.
func TestStrayRulesInOwnedRangeAreRemoved(t *testing.T) {
	r := newRig(t)
	r.sh(t, "ip rule add priority 1003 fwmark 0xca6d lookup 51821")
	r.sh(t, "ip rule add priority 1005 fwmark 0xca6e lookup main")
	if err := r.applier.Apply(context.Background(), desired(t)); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	r.requireApplied(t, desired(t))
}

// Rules outside the owned range belong to someone else and stay.
func TestForeignRulesOutsideRangeStay(t *testing.T) {
	r := newRig(t)
	r.sh(t, "ip rule add priority 88 fwmark 0x7 lookup main")
	defer r.sh(t, "ip rule del priority 88")
	if err := r.applier.Apply(context.Background(), desired(t)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.sh(t, "ip rule show"), "88:") {
		t.Fatal("a rule outside the owned range was removed")
	}
}

// A reboot: the kernel state is gone and so is the exit's interface — the
// agent recreates it only later. The boot restore must still bring back the
// table and the rules from disk alone.
func TestRestoreAfterReboot(t *testing.T) {
	r := newRig(t)
	want := desired(t)
	if err := r.applier.Apply(context.Background(), want); err != nil {
		t.Fatal(err)
	}
	r.sh(t, "nft delete table inet vnm && ip rule del priority 1000 && ip rule del priority 1001 && ip link del warp")

	if err := r.applier.Restore(context.Background()); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	r.requireApplied(t, apply.BootState(want))
	if got := r.sh(t, "nft list set inet vnm dead_exits"); !strings.Contains(got, "0x0000ca6c") {
		t.Fatalf("exit not dead after boot:\n%s", got)
	}
}

func TestHealthTouchesOnlyTheDeadSet(t *testing.T) {
	r := newRig(t)
	if err := r.applier.Apply(context.Background(), desired(t)); err != nil {
		t.Fatal(err)
	}
	before := r.sh(t, "nft -s list chain inet vnm decide")
	if err := r.applier.SetHealth(context.Background(), netstate.Health{DeadSlots: []int{0}, ResolverUp: true}); err != nil {
		t.Fatalf("SetHealth: %v", err)
	}
	if got := r.sh(t, "nft list set inet vnm dead_exits"); !strings.Contains(got, "0x0000ca6c") {
		t.Fatalf("dead set:\n%s", got)
	}
	if got := r.sh(t, "nft list set inet vnm dns_ports"); !strings.Contains(got, "53") {
		t.Fatalf("dns ports:\n%s", got)
	}
	if after := r.sh(t, "nft -s list chain inet vnm decide"); after != before {
		t.Fatal("a health change rewrote the classification")
	}
	if err := r.applier.SetHealth(context.Background(), netstate.Health{}); err != nil {
		t.Fatal(err)
	}
	if got := r.sh(t, "nft list set inet vnm dead_exits"); strings.Contains(got, "0x0000ca6c") {
		t.Fatalf("dead set not cleared:\n%s", got)
	}
	if got := r.sh(t, "nft list set inet vnm dns_ports"); strings.Contains(got, "53") {
		t.Fatalf("dns ports not cleared:\n%s", got)
	}
}

// The exit interface disappears under an applied policy, and the next apply
// wants a route into it. The apply fails, the rollback fails for the same
// reason — and the node must still be fail-closed: rules go in before routes,
// so the unreachable rule survives both failures.
func TestMissingExitInterfaceFailsClosed(t *testing.T) {
	r := newRig(t)
	want := desired(t)
	if err := r.applier.Apply(context.Background(), want); err != nil {
		t.Fatal(err)
	}
	r.sh(t, "ip link del warp")

	if err := r.applier.Apply(context.Background(), want); err == nil {
		t.Fatal("route into a missing interface was accepted")
	}
	rules, err := r.rt.Rules(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(rules, netstate.ExitRules(0)[1]) {
		t.Fatalf("unreachable rule missing after a failed apply: %+v", rules)
	}
}

func TestUplinksAndDrift(t *testing.T) {
	r := newRig(t)
	r.sh(t, "ip link add up0 type dummy && ip link set up0 up && ip addr add 192.0.2.100/24 dev up0 && ip route add default via 192.0.2.254 dev up0")
	defer r.sh(t, "ip link del up0")
	uplinks, err := r.rt.Uplinks(context.Background())
	if err != nil || !slices.Equal(uplinks, []string{"up0"}) {
		t.Fatalf("Uplinks = %v, %v", uplinks, err)
	}

	want := desired(t)
	if err := r.applier.Apply(context.Background(), want); err != nil {
		t.Fatal(err)
	}
	if err := r.applier.Verify(context.Background(), want); err != nil {
		t.Fatalf("Verify right after apply: %v", err)
	}
	// Something outside the agent wipes the ruleset — `nft flush ruleset`.
	r.sh(t, "nft flush ruleset")
	if err := r.applier.Verify(context.Background(), want); !errors.Is(err, apply.ErrDiverged) {
		t.Fatalf("Verify after a flush: want ErrDiverged, got %v", err)
	}
}

func TestCountersCountConnections(t *testing.T) {
	r := newRig(t)
	if err := r.applier.Apply(context.Background(), desired(t)); err != nil {
		t.Fatal(err)
	}
	counters, err := r.fw.Counters(context.Background())
	if err != nil {
		t.Fatalf("Counters: %v", err)
	}
	if _, ok := counters["r0_ru_ip_4"]; !ok {
		t.Fatalf("decision counter missing: %v", counters)
	}
	if _, ok := counters["exit_down"]; !ok {
		t.Fatalf("exit_down counter missing: %v", counters)
	}
}

// A hand-made rule shares the agent's priorities (a hand-made WARP had
// 1000 lookup and 1001 blackhole, both without a mask). Deleting it must not
// take the agent's rule of the same priority — found on the pilot node, where
// the migration removed our unreachable rule and kept the old blackhole.
func TestDeleteForeignRuleKeepsOursAtSamePriority(t *testing.T) {
	r := newRig(t)
	if err := r.applier.Apply(context.Background(), desired(t)); err != nil {
		t.Fatal(err)
	}
	r.sh(t, "ip rule add priority 1001 fwmark 0xca6c blackhole && ip rule add priority 1000 fwmark 0xca6c lookup main")

	rules, err := r.rt.Rules(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, rl := range rules {
		if rl.Mask == 0 {
			if err := r.rt.DeleteRule(context.Background(), rl); err != nil {
				t.Fatalf("delete %+v: %v", rl, err)
			}
		}
	}
	got, err := r.rt.Rules(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := netstate.ExitRules(0)
	if !slices.Equal(got, want[:]) {
		t.Fatalf("rules after deleting the foreign ones = %+v, want only ours %+v", got, want)
	}
}

// What the resolver put into a dynamic set survives a policy change: emptying
// it would let connections to listed domains out directly until each domain
// is resolved again.
func TestDynamicSetsSurviveReplace(t *testing.T) {
	r := newRig(t)
	if err := r.applier.Apply(context.Background(), desired(t)); err != nil {
		t.Fatal(err)
	}
	r.sh(t, "nft add element inet vnm l_ru_suffix_d4 { 203.0.113.20, 203.0.113.21 }")

	next := desired(t)
	next.Classify.Observe = true // any change that replaces the table
	if err := r.applier.Apply(context.Background(), next); err != nil {
		t.Fatal(err)
	}
	got := r.sh(t, "nft list set inet vnm l_ru_suffix_d4")
	if !strings.Contains(got, "203.0.113.20") || !strings.Contains(got, "203.0.113.21") {
		t.Fatalf("resolver entries lost in the replace:\n%s", got)
	}
}

// `vnm test` reads membership and health back from the live table: prefixes
// and ranges of static sets, single addresses of dynamic ones, marks and ports.
func TestLiveReadsMembershipAndHealth(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	if err := r.applier.Apply(ctx, desired(t)); err != nil {
		t.Fatal(err)
	}
	if err := r.applier.SetHealth(ctx, netstate.Health{DeadSlots: []int{0}, ResolverUp: true}); err != nil {
		t.Fatal(err)
	}
	r.sh(t, "nft add element inet vnm l_ru_suffix_d4 { 203.0.113.20 }")

	inRU := testsupport.RURanges[0].Addr().Next()
	for addr, want := range map[netip.Addr]map[string]bool{
		inRU:                                {"ru_ip_4": true},
		netip.MustParseAddr("203.0.113.20"): {"ru_suffix_d4": true},
		netip.MustParseAddr("8.8.8.8"):      {},
	} {
		live, err := r.fw.Live(ctx, addr)
		if err != nil {
			t.Fatal(err)
		}
		if !live.Present || !slices.Equal(live.Health.DeadSlots, []int{0}) || !live.Health.ResolverUp {
			t.Fatalf("live = %+v", live)
		}
		for set, held := range live.Holding {
			if held != want[set] {
				t.Errorf("%s in %s = %t, want %t", addr, set, held, want[set])
			}
		}
	}
}

// Switching the egress off leaves the guard: the exit rules and every chain
// that touches a mark go, the guard's chain stays.
func TestEgressOffKeepsGuard(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	if err := r.applier.Apply(ctx, desired(t)); err != nil {
		t.Fatal(err)
	}
	in := testsupport.PlanInput()
	in.Policy.Mode = policy.ModeOff
	guardOnly := testsupport.MustPlan(t, in)
	if err := r.applier.Apply(ctx, guardOnly); err != nil {
		t.Fatalf("Apply guard only: %v", err)
	}
	r.requireApplied(t, guardOnly)
	chains := r.sh(t, "nft list table inet vnm")
	if !strings.Contains(chains, "chain guard") {
		t.Fatalf("guard chain gone:\n%s", chains)
	}
	for _, egress := range []string{"chain prerouting", "chain output", "chain exit_snat"} {
		if strings.Contains(chains, egress) {
			t.Errorf("%s stayed with the egress off", egress)
		}
	}
}
