// Package apply brings the kernel to a desired state and keeps the last state
// that was applied successfully (ТЗ §7.1).
//
// The order of the steps is the point of the package: at every intermediate
// moment the kernel must satisfy the invariants, because a crash or a failed
// command can leave it exactly there.
//
//   - Rules come first, unreachable before lookup: a mark that finds no route
//     fails instead of leaving through the uplink.
//   - Routes come next, before any packet is marked.
//   - The nft table is replaced in one transaction.
//   - Only then are objects the new state no longer needs removed — table first,
//     then routes, then rules, so nothing is marked towards a missing rule.
package apply

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/lib4u/vnm/internal/domain/netstate"
)

// Firewall is the nft side of the state.
type Firewall interface {
	// Check validates the state against the kernel without applying it.
	Check(ctx context.Context, s netstate.State) error
	// Apply replaces the agent's table with the state's classification and
	// health in one transaction.
	Apply(ctx context.Context, s netstate.State) error
	// SetHealth applies the health, touching nothing else.
	SetHealth(ctx context.Context, h netstate.Health) error
	// Remove deletes the agent's table. An absent table is not an error.
	Remove(ctx context.Context) error
	// Present reports whether the agent's table exists.
	Present(ctx context.Context) (bool, error)
}

// Router is the policy routing side of the state.
type Router interface {
	// Rules returns the rules in the owned priority range, whoever added them.
	Rules(ctx context.Context) ([]netstate.IPRule, error)
	AddRule(ctx context.Context, r netstate.IPRule) error
	DeleteRule(ctx context.Context, r netstate.IPRule) error
	// Routes returns the default routes in the owned tables.
	Routes(ctx context.Context) ([]netstate.Route, error)
	ReplaceRoute(ctx context.Context, r netstate.Route) error
	DeleteRoute(ctx context.Context, r netstate.Route) error
}

// Store keeps the last state that was applied and verified.
type Store interface {
	// LastGood returns the stored state; ok is false when there is none yet.
	LastGood() (s netstate.State, ok bool, err error)
	SaveLastGood(s netstate.State) error
}

// ErrDiverged means the kernel does not hold the state that was just applied.
var ErrDiverged = errors.New("kernel state diverges from the applied state")

// Applier applies states in the invariant-preserving order.
type Applier struct {
	fw    Firewall
	rt    Router
	store Store
}

// New returns an Applier.
func New(fw Firewall, rt Router, store Store) *Applier {
	return &Applier{fw: fw, rt: rt, store: store}
}

// Apply brings the kernel to desired and records it as the last good state.
// On failure it rolls back to the previous last good state and returns both
// errors.
func (a *Applier) Apply(ctx context.Context, desired netstate.State) error {
	if !desired.Empty() {
		if err := a.fw.Check(ctx, desired); err != nil {
			// Nothing was touched: no rollback needed.
			return fmt.Errorf("check: %w", err)
		}
	}
	if err := a.converge(ctx, desired); err != nil {
		return a.rollback(ctx, err)
	}
	if err := a.store.SaveLastGood(desired); err != nil {
		return fmt.Errorf("save last good state: %w", err)
	}
	return nil
}

// Restore re-applies the last good state, if any — at boot, before the network
// comes up, with nothing fetched and nothing planned.
func (a *Applier) Restore(ctx context.Context) error {
	last, ok, err := a.store.LastGood()
	if err != nil {
		return fmt.Errorf("load last good state: %w", err)
	}
	if !ok {
		return nil
	}
	return a.converge(ctx, BootState(last))
}

// BootState is the last good state as the kernel can hold it at boot, before
// the agent brings the exits up: their interfaces do not exist yet, so no
// route can point into them, and none of them has proven itself alive. Marked
// traffic is refused by the dead set — and, without the agent, by the
// unreachable rules — until the agent checks the exits (invariant I-2).
func BootState(s netstate.State) netstate.State {
	s.Routes = nil
	s.Health = FailClosed(s)
	return s
}

// FailClosed is the health that assumes nothing: every exit dead, DNS not
// redirected until the resolver is seen answering. The kernel holds it
// whenever nobody knows better — at boot, and after a rollback, whose last
// good health is as old as the last full apply.
func FailClosed(s netstate.State) netstate.Health {
	h := netstate.Health{DeadSlots: make([]int, 0, len(s.Classify.Exits))}
	for _, e := range s.Classify.Exits {
		h.DeadSlots = append(h.DeadSlots, e.Slot)
	}
	slices.Sort(h.DeadSlots)
	return h
}

// SetHealth applies the health of the applied state.
func (a *Applier) SetHealth(ctx context.Context, h netstate.Health) error {
	if err := a.fw.SetHealth(ctx, h); err != nil {
		return fmt.Errorf("set health: %w", err)
	}
	return nil
}

func (a *Applier) rollback(ctx context.Context, cause error) error {
	last, ok, err := a.store.LastGood()
	if err != nil {
		return errors.Join(cause, fmt.Errorf("rollback: load last good state: %w", err))
	}
	if !ok {
		// Nothing to go back to; the unreachable rules already applied keep
		// the node fail-closed.
		return cause
	}
	// The stored health is that of the last full apply; the agent applies
	// the current one right after.
	last.Health = FailClosed(last)
	if err := a.converge(ctx, last); err != nil {
		return errors.Join(cause, fmt.Errorf("rollback: %w", err))
	}
	return fmt.Errorf("rolled back to the last good state: %w", cause)
}

// converge makes the kernel hold target and verifies it.
func (a *Applier) converge(ctx context.Context, target netstate.State) error {
	current, err := a.rt.Rules(ctx)
	if err != nil {
		return fmt.Errorf("read rules: %w", err)
	}
	foreign, err := a.addRules(ctx, missingRules(current, target.Rules), missingRules(target.Rules, current))
	if err != nil {
		return err
	}
	for _, r := range target.Routes {
		if err := a.rt.ReplaceRoute(ctx, r); err != nil {
			return fmt.Errorf("route %+v: %w", r, err)
		}
	}
	if err := a.applyFirewall(ctx, target); err != nil {
		return err
	}
	if err := a.removeRoutes(ctx, target.Routes); err != nil {
		return err
	}
	if err := a.removeRules(ctx, foreign); err != nil {
		return err
	}
	return a.Verify(ctx, target)
}

func (a *Applier) applyFirewall(ctx context.Context, target netstate.State) error {
	if target.Empty() {
		if err := a.fw.Remove(ctx); err != nil {
			return fmt.Errorf("remove table: %w", err)
		}
		return nil
	}
	if err := a.fw.Apply(ctx, target); err != nil {
		return fmt.Errorf("apply table: %w", err)
	}
	return nil
}

// addRules adds rules unreachable-first: of the two rules of a slot, the
// higher priority number is the unreachable one. The foreign rules in the
// owned range stay until the agent's are in, so that whatever keeps the node
// closed meanwhile keeps doing it — except where the kernel refuses an
// agent's rule: a foreign rule at its priority that differs from it only in
// what the kernel does not compare, such as an inverted match, counts as the
// same rule. The foreign rules of that priority go first then, and the rule
// is added again; the agent's rule was missing anyway, so nothing of its own
// is lost in between. It returns the foreign rules still present.
func (a *Applier) addRules(ctx context.Context, rules, foreign []netstate.IPRule) ([]netstate.IPRule, error) {
	slices.SortFunc(rules, func(x, y netstate.IPRule) int { return y.Priority - x.Priority })
	for _, r := range rules {
		err := a.rt.AddRule(ctx, r)
		if err == nil {
			continue
		}
		atPriority := func(x netstate.IPRule) bool { return x.Priority == r.Priority }
		blocking := slices.DeleteFunc(slices.Clone(foreign), func(x netstate.IPRule) bool { return !atPriority(x) })
		if len(blocking) == 0 {
			return foreign, fmt.Errorf("add rule %+v: %w", r, err)
		}
		if err := a.removeRules(ctx, blocking); err != nil {
			return foreign, err
		}
		foreign = slices.DeleteFunc(foreign, atPriority)
		if err := a.rt.AddRule(ctx, r); err != nil {
			return foreign, fmt.Errorf("add rule %+v: %w", r, err)
		}
	}
	return foreign, nil
}

// removeRules removes rules lookup-first, the reverse of addRules.
func (a *Applier) removeRules(ctx context.Context, rules []netstate.IPRule) error {
	slices.SortFunc(rules, func(x, y netstate.IPRule) int { return x.Priority - y.Priority })
	for _, r := range rules {
		if err := a.rt.DeleteRule(ctx, r); err != nil {
			return fmt.Errorf("delete rule %+v: %w", r, err)
		}
	}
	return nil
}

// removeRoutes deletes every route in the owned tables that keep is missing.
func (a *Applier) removeRoutes(ctx context.Context, keep []netstate.Route) error {
	routes, err := a.rt.Routes(ctx)
	if err != nil {
		return fmt.Errorf("read routes: %w", err)
	}
	for _, r := range routes {
		if slices.Contains(keep, r) {
			continue
		}
		if err := a.rt.DeleteRoute(ctx, r); err != nil {
			return fmt.Errorf("delete route %+v: %w", r, err)
		}
	}
	return nil
}

// Verify reads the kernel back and compares it with target: the owned rules and
// routes must match exactly, and the table must exist exactly when the state
// owns one. It is how the agent notices that something outside it removed or
// replaced its objects.
func (a *Applier) Verify(ctx context.Context, target netstate.State) error {
	rules, err := a.rt.Rules(ctx)
	if err != nil {
		return fmt.Errorf("verify rules: %w", err)
	}
	if !sameRules(rules, target.Rules) {
		return fmt.Errorf("%w: rules %+v, want %+v", ErrDiverged, rules, target.Rules)
	}

	routes, err := a.rt.Routes(ctx)
	if err != nil {
		return fmt.Errorf("verify routes: %w", err)
	}
	if !sameRoutes(routes, target.Routes) {
		return fmt.Errorf("%w: routes %+v, want %+v", ErrDiverged, routes, target.Routes)
	}

	present, err := a.fw.Present(ctx)
	if err != nil {
		return fmt.Errorf("verify table: %w", err)
	}
	if present == target.Empty() {
		return fmt.Errorf("%w: table present=%t for a state that owns %s", ErrDiverged, present, ownsWhat(target))
	}
	return nil
}

func ownsWhat(s netstate.State) string {
	if s.Empty() {
		return "nothing"
	}
	return "a table"
}

// missingRules returns the rules of want that have lacks.
func missingRules(have, want []netstate.IPRule) []netstate.IPRule {
	var out []netstate.IPRule
	for _, r := range want {
		if !slices.Contains(have, r) {
			out = append(out, r)
		}
	}
	return out
}

func sameRules(a, b []netstate.IPRule) bool { return sameElements(a, b) }

func sameRoutes(a, b []netstate.Route) bool { return sameElements(a, b) }

// sameElements reports whether a and b hold the same elements the same number
// of times, in any order.
func sameElements[T comparable](a, b []T) bool {
	if len(a) != len(b) {
		return false
	}
	count := make(map[T]int, len(a))
	for _, x := range a {
		count[x]++
	}
	for _, x := range b {
		if count[x]--; count[x] < 0 {
			return false
		}
	}
	return true
}
