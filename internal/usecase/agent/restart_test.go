package agent_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/lib4u/vnm/internal/domain/netstate"
	"github.com/lib4u/vnm/internal/domain/policy"
	"github.com/lib4u/vnm/internal/usecase/apply"
)

// lastGood is what a previous agent left on disk: the state it applied.
func lastGood(t *testing.T) netstate.State {
	t.Helper()
	prev := newRig()
	prev.pass()
	return prev.kernel.applies[0]
}

// A restarted agent whose policy cannot be planned yet still refuses a dead
// exit of the state in force (I-2), from the first pass.
func TestRestartKeepsHealthWhilePolicyWaits(t *testing.T) {
	r := newRig()
	r.store.last, r.store.ok = lastGood(t), true
	r.lists.err = errors.New("github unreachable")
	r.cfg.version = "v2" // a new policy whose lists never resolved
	r.exits.healthy = false
	r.pass()
	if len(r.kernel.applies) != 0 {
		t.Fatalf("applied without lists: %d", len(r.kernel.applies))
	}
	if len(r.kernel.health) != 1 || !slices.Equal(r.kernel.health[0].DeadSlots, []int{0}) {
		t.Fatalf("health = %+v: the dead exit is not refused", r.kernel.health)
	}
	if r.metrics.last.PolicyApplied {
		t.Fatal("the policy is reported applied")
	}
}

// A restarted agent checks lists against the sizes in force, not only their
// absolute bounds: a collapsed copy rejected before the restart must not go
// in after it (ТЗ §7.4).
func TestRestartKeepsListBounds(t *testing.T) {
	r := newRig()
	r.store.last, r.store.ok = lastGood(t), true
	r.pass()
	if r.lists.previous["ru_ip"].V4 == 0 {
		t.Fatalf("previous sizes = %v: the bounds of the lists in force were lost", r.lists.previous)
	}
}

// The first pass after a restart replaces a kernel that lost its routes at
// boot without calling it drift, and applies the current health even when it
// equals the stored one: the stored health is as old as the last full apply.
func TestRestartCatchesUpWithoutDrift(t *testing.T) {
	r := newRig()
	r.store.last, r.store.ok = lastGood(t), true
	r.kernel.verifyErr = apply.ErrDiverged
	r.pass()
	if r.agent == nil || len(r.kernel.applies) != 1 || r.metrics.last.Drift != 0 {
		t.Fatalf("applies %d, drift %d", len(r.kernel.applies), r.metrics.last.Drift)
	}

	r = newRig()
	r.store.last, r.store.ok = lastGood(t), true
	r.pass()
	if len(r.kernel.applies) != 0 || len(r.kernel.health) != 1 {
		t.Fatalf("applies %d, health %+v: the stored health was taken for the kernel's", len(r.kernel.applies), r.kernel.health)
	}
}

// A new build applies the state anew on its first pass, though the policy
// did not change: it may render it differently — a chain an old build did not
// have would otherwise never reach the kernel. A restart of the same build
// does not.
func TestUpgradeAppliesAnew(t *testing.T) {
	r := newRig()
	r.store.last, r.store.ok = lastGood(t), true
	r.build("v2")
	r.pass()
	r.pass()
	if len(r.kernel.applies) != 1 || r.kernel.applies[0].Agent != "v2" {
		t.Fatalf("applies %d after an upgrade", len(r.kernel.applies))
	}
}

// Exits the last good state had and the policy no longer has lose their
// interfaces; an interface the policy still uses is kept.
func TestRestartRetiresDroppedExits(t *testing.T) {
	r := newRig()
	last := lastGood(t)
	last.Classify.Exits = append(last.Classify.Exits, netstate.Exit{Slot: 1, Iface: "wg-old"})
	r.store.last, r.store.ok = last, true
	r.pass()
	r.pass()
	if !slices.Equal(r.exits.retired, []string{"wg-old"}) {
		t.Fatalf("retired %v", r.exits.retired)
	}
}

// A failed apply is rolled back with every exit dead; the real health goes
// back at once, or a live exit would be refused for as long as the bad
// policy stays.
func TestFailedApplyResyncsHealth(t *testing.T) {
	r := newRig()
	r.pass()
	r.kernel.applyErr = errors.New("nft: syntax error")
	r.cfg.cfg.Mode, r.cfg.version = policy.ModeObserve, "v2"
	r.pass()
	if len(r.kernel.health) != 1 || len(r.kernel.health[0].DeadSlots) != 0 {
		t.Fatalf("health after the failed apply = %+v", r.kernel.health)
	}
}

// Drift is a kernel that stopped holding a state it held; a failed read is
// not drift.
func TestDriftCountsOnlyDivergence(t *testing.T) {
	r := newRig()
	r.pass()
	r.kernel.verifyErr = errors.New("ip: timeout")
	r.pass()
	r.kernel.verifyErr = apply.ErrDiverged
	r.pass()
	if d := r.metrics.last.Drift; d != 1 {
		t.Fatalf("drift = %d, want 1", d)
	}
}

// A resolver that failed to take the state is retried every pass, not only
// at the next change.
func TestResolverApplyIsRetried(t *testing.T) {
	r := newRig()
	r.dns.applyErr = errors.New("systemctl: timeout")
	r.pass()
	r.dns.applyErr = nil
	r.pass()
	r.pass()
	if len(r.dns.applied) != 2 {
		t.Fatalf("resolver applies = %d, want a retry and then none", len(r.dns.applied))
	}
}

// A failed counter read republishes the last counters: a gap would read as
// a counter reset.
func TestCountersKeptOnReadFailure(t *testing.T) {
	r := newRig()
	r.pass()
	r.kernel.countersErr = errors.New("nft: busy")
	r.pass()
	if s := r.metrics.last; s.Counters["r0_ru_ip_4"] != 7 || s.Guard.Refused["scanners"] != 5 {
		t.Fatalf("snapshot = %+v", s)
	}
}

// The agent's own recreation of an exit drops the routes through it; putting
// them back is not drift.
func TestOwnRecreateIsNotDrift(t *testing.T) {
	r := newRig()
	r.pass()
	r.exits.recreated = true
	r.kernel.verifyErr = apply.ErrDiverged
	r.pass()
	if d := r.metrics.last.Drift; d != 0 || len(r.kernel.applies) != 2 {
		t.Fatalf("drift %d, applies %d", d, len(r.kernel.applies))
	}
}
