package agent

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"

	"github.com/lib4u/vnm/internal/domain/netstate"
	"github.com/lib4u/vnm/internal/usecase/apply"
	"github.com/lib4u/vnm/internal/usecase/exits"
	"github.com/lib4u/vnm/internal/usecase/planner"
)

// converge brings the kernel to the policy. When the policy cannot be planned
// yet — its lists are not resolved, the uplink is unknown — or cannot be
// applied, the state applied before stays, and the health of its exits keeps
// being updated: a dead exit must be refused whatever else is pending (I-2).
func (a *Agent) converge(ctx context.Context, statuses []exits.Status) error {
	desired, err := a.desired(ctx, statuses)
	if err != nil {
		return errors.Join(fmt.Errorf("policy not applied: %w", err), a.syncHealth(ctx, statuses))
	}

	switch {
	case a.applied == nil || !sameIgnoringHealth(desired, *a.applied):
		err = a.apply(ctx, desired, statuses, "state changed")
	default:
		if verr := a.d.Kernel.Verify(ctx, desired); verr != nil {
			// Before this process saw the kernel hold the state, a difference
			// is the restart catching up (boot keeps no routes), not drift;
			// nor are the routes the agent's own recreation of an exit took.
			if a.trusted && errors.Is(verr, apply.ErrDiverged) && !recreatedAny(statuses) {
				a.drift++
			}
			err = a.apply(ctx, desired, statuses, "the kernel does not hold the applied state")
			break
		}
		a.trusted = true
		if !a.healthSynced || !desired.Health.Equal(a.applied.Health) {
			err = a.setHealth(ctx, desired.Health)
		}
	}
	if err != nil {
		return err
	}
	return a.syncResolver(ctx)
}

func (a *Agent) desired(ctx context.Context, statuses []exits.Status) (netstate.State, error) {
	if err := a.resolveLists(ctx); err != nil {
		return netstate.State{}, err
	}
	uplinks, err := a.d.Uplinks.Uplinks(ctx)
	if err != nil {
		return netstate.State{}, fmt.Errorf("detect uplinks: %w", err)
	}
	listen, err := a.d.Listening.Listening()
	if err != nil {
		return netstate.State{}, fmt.Errorf("read listening ports: %w", err)
	}
	exitStatus := make(map[string]planner.ExitStatus, len(statuses))
	for _, st := range statuses {
		exitStatus[st.Name] = planner.ExitStatus{Present: st.Present, Healthy: st.Healthy}
	}
	var resolver planner.ResolverStatus
	if a.cfg.EgressActive() && a.cfg.UsesDomains() {
		if resolver.UID, err = a.d.Resolver.UID(); err != nil {
			return netstate.State{}, fmt.Errorf("resolver user: %w", err)
		}
		resolver.Up = a.d.Resolver.Up(ctx, a.cfg.DNS.Port)
	}
	state, err := planner.Plan(planner.Input{
		Policy:   a.cfg,
		Ranges:   a.ranges,
		Domains:  a.domains,
		Uplinks:  uplinks,
		Listen:   listen,
		Exits:    exitStatus,
		Resolver: resolver,
	})
	if err != nil {
		return netstate.State{}, err
	}
	state.Agent = a.d.Build
	return state, nil
}

// apply replaces the kernel's state. A failed apply is rolled back to the last
// good state with every exit taken for dead; the health those exits really
// have is applied right after, so a live exit is not refused for the length
// of a bad policy.
func (a *Agent) apply(ctx context.Context, desired netstate.State, statuses []exits.Status, why string) error {
	if err := a.d.Kernel.Apply(ctx, desired); err != nil {
		a.applyErrors++
		a.trusted, a.healthSynced = false, false
		return errors.Join(fmt.Errorf("apply (%s): %w", why, err), a.syncHealth(ctx, statuses))
	}
	a.applied = &desired
	a.trusted, a.healthSynced, a.resolverSynced = true, true, false
	a.d.Log.Info("state applied", "reason", why, "mode", a.cfg.Mode.String(), "guard", a.cfg.Guard.Mode.String(),
		"p2p", a.cfg.P2P.Mode.String(), "dead_exits", desired.Health.DeadSlots, "resolver_up", desired.Health.ResolverUp)
	return nil
}

// syncResolver makes the resolver serve the applied state — after the kernel,
// since its sets exist only once the table does — and retries every pass
// until that succeeds.
func (a *Agent) syncResolver(ctx context.Context) error {
	if a.resolverSynced {
		return nil
	}
	if err := a.d.Resolver.Apply(ctx, *a.applied); err != nil {
		return fmt.Errorf("resolver: %w", err)
	}
	a.resolverSynced = true
	return nil
}

func recreatedAny(statuses []exits.Status) bool {
	return slices.ContainsFunc(statuses, func(st exits.Status) bool { return st.Recreated })
}

// sameIgnoringHealth compares two states apart from their health: health is
// applied through its sets alone, never by replacing the table.
func sameIgnoringHealth(a, b netstate.State) bool {
	a.Health, b.Health = netstate.Health{}, netstate.Health{}
	return reflect.DeepEqual(a, b)
}
