package agent

import (
	"context"

	"github.com/lib4u/vnm/internal/domain/netstate"
	"github.com/lib4u/vnm/internal/usecase/exits"
	"github.com/lib4u/vnm/internal/usecase/planner"
)

// syncHealth brings the kernel's health for the applied state up to the
// exits' checks and the resolver — also when the policy cannot be planned.
func (a *Agent) syncHealth(ctx context.Context, statuses []exits.Status) error {
	if a.applied == nil {
		return nil
	}
	healthy := make(map[int]bool, len(statuses))
	for _, st := range statuses {
		healthy[st.Slot] = st.Healthy
	}
	h := netstate.Health{
		DeadSlots:  planner.DeadSlots(a.applied.Classify.Exits, healthy),
		ResolverUp: a.applied.DNS.Enabled() && a.d.Resolver.Up(ctx, a.applied.DNS.Port),
	}
	if a.healthSynced && h.Equal(a.applied.Health) {
		return nil
	}
	return a.setHealth(ctx, h)
}

func (a *Agent) setHealth(ctx context.Context, h netstate.Health) error {
	if err := a.d.Kernel.SetHealth(ctx, h); err != nil {
		a.applyErrors++
		a.healthSynced = false
		return err
	}
	a.applied.Health, a.healthSynced = h, true
	a.d.Log.Info("health applied", "dead_exits", h.DeadSlots, "resolver_up", h.ResolverUp)
	return nil
}
