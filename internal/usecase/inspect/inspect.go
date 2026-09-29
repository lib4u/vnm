// Package inspect explains what the node does with a destination (ТЗ §8,
// `vnm test`) without sending it any traffic: the classification order comes
// from the applied state, set membership and health from the live kernel — the
// same inputs the packet path uses.
package inspect

import (
	"context"
	"fmt"
	"net/netip"
	"slices"

	"github.com/lib4u/vnm/internal/domain/netstate"
)

// Live is the agent's table as the kernel holds it now.
type Live struct {
	// Present is false when the table is gone: nothing is classified.
	Present bool
	// Holding names the planned sets that hold the address.
	Holding map[string]bool
	Health  netstate.Health
}

// Kernel reads the live table.
type Kernel interface {
	Live(ctx context.Context, addr netip.Addr) (Live, error)
}

// Store holds the applied state.
type Store interface {
	LastGood() (s netstate.State, ok bool, err error)
}

// Outcome is where a new connection to the destination goes.
type Outcome uint8

const (
	OutcomeUnknown Outcome = iota
	// OutcomeDirect leaves through the uplink.
	OutcomeDirect
	// OutcomeExit leaves through Explanation.Exit.
	OutcomeExit
	// OutcomeBlock is rejected by the policy.
	OutcomeBlock
	// OutcomeRefused is bound for an exit declared dead, and rejected at once.
	OutcomeRefused
	// OutcomeUnmanaged means the agent's table is absent.
	OutcomeUnmanaged
)

// Match is a decision whose set holds the address.
type Match struct {
	List    string
	Set     string
	Verdict netstate.Verdict
}

// Explanation is the whole decision for one address.
type Explanation struct {
	Addr netip.Addr
	// Exempt addresses are never classified.
	Exempt bool
	// Matches lists every decision matching the address in evaluation order;
	// the first one decides.
	Matches []Match
	// Exit is the exit the decision names, if any.
	Exit *netstate.Exit
	// Observe means the decision is only counted: the connection leaves
	// directly whatever Would says.
	Observe bool
	// Would is the outcome the policy asks for; Outcome is what happens.
	Would   Outcome
	Outcome Outcome
	// Guarded is the guard rule that refuses a new connection from Addr
	// arriving on an uplink; nil when the guard lets it in.
	Guarded *netstate.GuardRule
	// GuardObserve means the guard only counts: Guarded is let in anyway.
	GuardObserve bool
}

// Inspector explains destinations.
type Inspector struct {
	kernel Kernel
	store  Store
}

// New returns an Inspector.
func New(k Kernel, s Store) *Inspector {
	return &Inspector{kernel: k, store: s}
}

// Explain returns the decision for addr.
func (in *Inspector) Explain(ctx context.Context, addr netip.Addr) (Explanation, error) {
	addr = addr.Unmap()
	ex := Explanation{Addr: addr}
	state, ok, err := in.store.LastGood()
	if err != nil {
		return ex, fmt.Errorf("applied state: %w", err)
	}
	live, err := in.kernel.Live(ctx, addr)
	if err != nil {
		return ex, fmt.Errorf("live table: %w", err)
	}
	if !ok || !live.Present {
		ex.Would, ex.Outcome = OutcomeUnmanaged, OutcomeUnmanaged
		return ex, nil
	}

	c := state.Classify
	ex.Observe = c.Observe
	ex.Exempt = slices.ContainsFunc(c.Exempt, func(p netip.Prefix) bool { return p.Contains(addr) })
	for _, d := range c.Decisions {
		if live.Holding[d.Set] {
			ex.Matches = append(ex.Matches, Match{List: d.List, Set: d.Set, Verdict: d.Verdict})
		}
	}

	ex.Would = OutcomeDirect
	if !ex.Exempt && len(ex.Matches) > 0 {
		ex.Would, ex.Exit = outcome(ex.Matches[0].Verdict, c.Exits, live.Health)
	}
	ex.Outcome = ex.Would
	if ex.Observe {
		ex.Outcome = OutcomeDirect
	}

	ex.GuardObserve = state.Guard.Observe
	if !ex.Exempt {
		for _, r := range state.Guard.Rules {
			if live.Holding[r.Set] {
				ex.Guarded = &r
				break
			}
		}
	}
	return ex, nil
}

func outcome(v netstate.Verdict, exits []netstate.Exit, h netstate.Health) (Outcome, *netstate.Exit) {
	switch v {
	case netstate.VerdictDirect:
		return OutcomeDirect, nil
	case netstate.VerdictBlock:
		return OutcomeBlock, nil
	}
	for _, e := range exits {
		if netstate.VerdictExit(e.Slot) != v {
			continue
		}
		if slices.Contains(h.DeadSlots, e.Slot) {
			return OutcomeRefused, &e
		}
		return OutcomeExit, &e
	}
	return OutcomeUnknown, nil
}
