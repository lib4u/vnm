package apply_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/lib4u/vnm/internal/domain/netstate"
)

var (
	errInjected = errors.New("injected failure")
	errExists   = errors.New("rule exists")
)

// kernel fakes both the nft and the routing side. After every operation it
// checks the invariant the apply order exists for: while the table can mark
// traffic towards an exit, that exit's unreachable rule is in place.
type kernel struct {
	t      *testing.T
	rules  []netstate.IPRule
	routes []netstate.Route
	table  *netstate.State // nil: no table
	dead   []int

	ops []string
	// failOn makes the named operation fail once.
	failOn string
}

func newKernel(t *testing.T) *kernel { return &kernel{t: t} }

func (k *kernel) record(op string) error {
	k.ops = append(k.ops, op)
	if k.failOn == op {
		k.failOn = ""
		return errInjected
	}
	return nil
}

func (k *kernel) checkInvariant() {
	k.t.Helper()
	if k.table == nil {
		return
	}
	for _, e := range k.table.Classify.Exits {
		unreachable := netstate.ExitRules(e.Slot)[1]
		if !slices.Contains(k.rules, unreachable) {
			k.t.Errorf("after %v: table marks towards slot %d without its unreachable rule", k.ops, e.Slot)
		}
	}
}

func (k *kernel) Check(context.Context, netstate.State) error { return k.record("check") }

func (k *kernel) Apply(_ context.Context, s netstate.State) error {
	if err := k.record("table apply"); err != nil {
		return err
	}
	k.table = &s
	k.dead = slices.Clone(s.Health.DeadSlots)
	k.checkInvariant()
	return nil
}

func (k *kernel) SetHealth(_ context.Context, h netstate.Health) error {
	if err := k.record("health"); err != nil {
		return err
	}
	k.dead = slices.Clone(h.DeadSlots)
	return nil
}

func (k *kernel) Remove(context.Context) error {
	if err := k.record("table remove"); err != nil {
		return err
	}
	k.table = nil
	return nil
}

func (k *kernel) Present(context.Context) (bool, error) { return k.table != nil, nil }

func (k *kernel) Rules(context.Context) ([]netstate.IPRule, error) { return slices.Clone(k.rules), nil }

func (k *kernel) AddRule(_ context.Context, r netstate.IPRule) error {
	if err := k.record(fmt.Sprintf("rule add %d", r.Priority)); err != nil {
		return err
	}
	if slices.ContainsFunc(k.rules, func(x netstate.IPRule) bool { return sameForKernel(x, r) }) {
		return errExists
	}
	k.rules = append(k.rules, r)
	k.checkInvariant()
	return nil
}

// sameForKernel models the kernel refusing a rule it already holds: it does
// not compare everything a rule carries — an inverted match, the protocol —
// so a foreign rule that differs from the agent's only in Extra is taken for
// the same rule.
func sameForKernel(x, y netstate.IPRule) bool {
	x.Extra, y.Extra = "", ""
	return x == y
}

func (k *kernel) DeleteRule(_ context.Context, r netstate.IPRule) error {
	if err := k.record(fmt.Sprintf("rule del %d", r.Priority)); err != nil {
		return err
	}
	k.rules = slices.DeleteFunc(k.rules, func(x netstate.IPRule) bool { return x == r })
	k.checkInvariant()
	return nil
}

func (k *kernel) Routes(context.Context) ([]netstate.Route, error) {
	return slices.Clone(k.routes), nil
}

func (k *kernel) ReplaceRoute(_ context.Context, r netstate.Route) error {
	if err := k.record(fmt.Sprintf("route replace %d", r.Table)); err != nil {
		return err
	}
	k.routes = slices.DeleteFunc(k.routes, func(x netstate.Route) bool { return x.Table == r.Table })
	k.routes = append(k.routes, r)
	return nil
}

func (k *kernel) DeleteRoute(_ context.Context, r netstate.Route) error {
	if err := k.record(fmt.Sprintf("route del %d", r.Table)); err != nil {
		return err
	}
	k.routes = slices.DeleteFunc(k.routes, func(x netstate.Route) bool { return x == r })
	return nil
}

// store fakes the last-good state file.
type store struct {
	state *netstate.State
}

func (s *store) LastGood() (netstate.State, bool, error) {
	if s.state == nil {
		return netstate.State{}, false, nil
	}
	return *s.state, true, nil
}

func (s *store) SaveLastGood(st netstate.State) error {
	s.state = &st
	return nil
}
