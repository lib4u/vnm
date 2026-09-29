package agent

import (
	"context"

	"github.com/lib4u/vnm/internal/domain/netstate"
	"github.com/lib4u/vnm/internal/usecase/exits"
)

func (a *Agent) publish(ctx context.Context, configValid bool, statuses []exits.Status) {
	snap := Snapshot{
		ConfigValid:   configValid,
		PolicyApplied: configValid && a.version != "" && a.policyErr == nil,
		ListsCurrent:  a.listsCurrent,
		Mode:          a.cfg.Mode,
		Exits:         statuses,
		Lists:         a.listStatuses(),
		Guard:         GuardSnapshot{Mode: a.cfg.Guard.Mode},
		ApplyErrors:   a.applyErrors,
		Drift:         a.drift,
		LastReconcile: a.d.Now(),
	}
	if a.applied != nil {
		snap.Resolver = ResolverSnapshot{Enabled: a.applied.DNS.Enabled(), Up: a.applied.Health.ResolverUp}
		counters, err := a.d.Counters.Counters(ctx)
		if err != nil {
			// The last counters again: a gap would read as a counter reset.
			a.d.Log.Warn("read counters", "error", err)
		} else {
			a.counters = counters
		}
		snap.Counters = a.counters
		snap.Guard.Refused = refused(a.applied.Guard, a.counters)
	}
	if err := a.d.Metrics.Publish(snap); err != nil {
		a.d.Log.Warn("publish metrics", "error", err)
	}
}

// refused sums the guard's counters per list.
func refused(g netstate.Guard, counters map[string]uint64) map[string]uint64 {
	if !g.Active() {
		return nil
	}
	out := map[string]uint64{}
	for _, r := range g.Rules {
		out[r.List] += counters[r.Counter]
	}
	return out
}
