package apply_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/lib4u/vnm/internal/domain/netstate"
	"github.com/lib4u/vnm/internal/testsupport"
	"github.com/lib4u/vnm/internal/usecase/apply"
)

func desired(t *testing.T) netstate.State {
	t.Helper()
	return testsupport.MustPlan(t, testsupport.PlanInput())
}

func setup(t *testing.T) (*kernel, *store, *apply.Applier) {
	k, s := newKernel(t), &store{}
	return k, s, apply.New(k, k, s)
}

func TestApplyFreshNodeInSafeOrder(t *testing.T) {
	k, s, a := setup(t)
	want := desired(t)

	if err := a.Apply(context.Background(), want); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	wantOps := []string{"check", "rule add 1001", "rule add 1000", "route replace 51820", "table apply"}
	if !slices.Equal(k.ops, wantOps) {
		t.Fatalf("ops = %v, want %v", k.ops, wantOps)
	}
	if s.state == nil {
		t.Fatal("last good state not saved")
	}
}

func TestApplyIsIdempotent(t *testing.T) {
	k, _, a := setup(t)
	want := desired(t)
	if err := a.Apply(context.Background(), want); err != nil {
		t.Fatal(err)
	}
	k.ops = nil
	if err := a.Apply(context.Background(), want); err != nil {
		t.Fatal(err)
	}
	// Rules are already there; the route and table are rewritten in place.
	wantOps := []string{"check", "route replace 51820", "table apply"}
	if !slices.Equal(k.ops, wantOps) {
		t.Fatalf("second apply ops = %v, want %v", k.ops, wantOps)
	}
}

// Removing everything goes in reverse: the table stops marking first, the
// lookup rule goes before the unreachable one.
func TestApplyOffRemovesInReverse(t *testing.T) {
	k, _, a := setup(t)
	if err := a.Apply(context.Background(), desired(t)); err != nil {
		t.Fatal(err)
	}
	k.ops = nil
	if err := a.Apply(context.Background(), netstate.State{}); err != nil {
		t.Fatalf("Apply off: %v", err)
	}
	wantOps := []string{"table remove", "route del 51820", "rule del 1000", "rule del 1001"}
	if !slices.Equal(k.ops, wantOps) {
		t.Fatalf("ops = %v, want %v", k.ops, wantOps)
	}
	if len(k.rules) != 0 || len(k.routes) != 0 || k.table != nil {
		t.Fatalf("kernel not empty: %+v %+v %v", k.rules, k.routes, k.table)
	}
}

// A state the kernel refuses is not applied at all.
func TestApplyCheckFailureTouchesNothing(t *testing.T) {
	k, s, a := setup(t)
	k.failOn = "check"
	if err := a.Apply(context.Background(), desired(t)); !errors.Is(err, errInjected) {
		t.Fatalf("want injected error, got %v", err)
	}
	if !slices.Equal(k.ops, []string{"check"}) || s.state != nil {
		t.Fatalf("ops %v, saved %v", k.ops, s.state)
	}
}

// A failure halfway rolls the kernel back to the last good state, and the
// failed state is not recorded as good.
func TestApplyFailureRollsBack(t *testing.T) {
	k, s, a := setup(t)
	good := desired(t)
	if err := a.Apply(context.Background(), good); err != nil {
		t.Fatal(err)
	}

	next := desired(t)
	next.Classify.Observe = true
	k.failOn = "table apply"
	err := a.Apply(context.Background(), next)
	if !errors.Is(err, errInjected) {
		t.Fatalf("want injected error, got %v", err)
	}
	if k.table == nil || k.table.Classify.Observe {
		t.Fatalf("kernel table after rollback = %+v, want the good state", k.table)
	}
	if s.state.Classify.Observe {
		t.Fatal("failed state recorded as last good")
	}
	// The stored health is as old as the last full apply: the rollback
	// assumes nothing, and the agent applies the real health after it.
	if !slices.Equal(k.dead, []int{0}) || k.table.Health.ResolverUp {
		t.Fatalf("health after rollback: dead %v, resolver up %t", k.dead, k.table.Health.ResolverUp)
	}
}

// Without a last good state there is nothing to roll back to; the rules added
// before the failure keep the node fail-closed.
func TestApplyFailureWithoutLastGood(t *testing.T) {
	k, _, a := setup(t)
	k.failOn = "table apply"
	if err := a.Apply(context.Background(), desired(t)); !errors.Is(err, errInjected) {
		t.Fatalf("want injected error, got %v", err)
	}
	if !slices.Contains(k.rules, netstate.ExitRules(0)[1]) {
		t.Fatal("unreachable rule missing after a failed first apply")
	}
}

// Rules someone else left in the owned range are removed; the node owns it.
func TestApplyRemovesStrayOwnedRules(t *testing.T) {
	k, _, a := setup(t)
	stray := netstate.IPRule{Priority: 1003, Mark: 0xca6d, Action: netstate.RuleLookup, Table: 51821}
	k.rules = []netstate.IPRule{stray}
	if err := a.Apply(context.Background(), desired(t)); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(k.rules, stray) {
		t.Fatalf("stray rule survived: %+v", k.rules)
	}
}

// A foreign rule the kernel takes for the agent's — it differs only in an
// inverted match — refuses the agent's rule until it is gone: it goes first,
// and only it; the rest of the foreign rules wait for the agent's to be in.
func TestApplyRemovesForeignTwinBeforeAddingOurs(t *testing.T) {
	k, _, a := setup(t)
	twin := netstate.ExitRules(0)[1]
	twin.Extra = "not"
	stray := netstate.IPRule{Priority: 1003, Mark: 0xca6d, Action: netstate.RuleLookup, Table: 51821}
	k.rules = []netstate.IPRule{twin, stray}
	if err := a.Apply(context.Background(), desired(t)); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	wantOps := []string{
		"check", "rule add 1001", "rule del 1001", "rule add 1001", "rule add 1000",
		"route replace 51820", "table apply", "rule del 1003",
	}
	if !slices.Equal(k.ops, wantOps) {
		t.Fatalf("ops = %v, want %v", k.ops, wantOps)
	}
	if want := netstate.ExitRules(0); !slices.Equal(k.rules, []netstate.IPRule{want[1], want[0]}) {
		t.Fatalf("rules = %+v, want only ours", k.rules)
	}
}

// At boot the exits' interfaces do not exist yet: restoring their routes would
// fail and leave the node with no table at all — every connection direct
// (I-1). The restore installs everything but the routes, with every exit dead.
func TestRestoreAppliesLastGoodWithoutRoutes(t *testing.T) {
	k, s, a := setup(t)
	good := desired(t)
	s.state = &good

	if err := a.Restore(context.Background()); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if k.table == nil || len(k.rules) != 2 {
		t.Fatalf("kernel after restore: table %v rules %+v", k.table, k.rules)
	}
	if len(k.routes) != 0 || slices.Contains(k.ops, "route replace 51820") {
		t.Fatalf("restore touched exit routes: %+v %v", k.routes, k.ops)
	}
	if !slices.Equal(k.dead, []int{0}) {
		t.Fatalf("dead slots after restore = %v, want every exit dead", k.dead)
	}
	if slices.Contains(k.ops, "check") {
		t.Fatal("restore must not depend on anything but the stored state")
	}
}

func TestRestoreWithoutLastGoodDoesNothing(t *testing.T) {
	k, _, a := setup(t)
	if err := a.Restore(context.Background()); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if len(k.ops) != 0 {
		t.Fatalf("ops = %v", k.ops)
	}
}
