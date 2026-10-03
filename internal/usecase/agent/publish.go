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
		P2P:           P2PSnapshot{Mode: a.cfg.P2P.Mode},
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
		snap.P2P.Refused = p2pRefused(a.applied.P2P, a.counters)
	}
	if a.d.P2P != nil {
		a.d.P2P.Update(ctx, a.cfg.P2P, configValid && a.applied != nil && a.applied.P2P.Active())
		st := a.d.P2P.Stats()
		snap.P2P.NDPI = a.cfg.P2P.Active() && a.cfg.P2P.NDPI.Enabled
		snap.P2P.Connected, snap.P2P.Detections, snap.P2P.Peers, snap.P2P.Bans = st.Connected, st.Detections, st.Peers, st.Bans
	}
	if err := a.d.Metrics.Publish(snap); err != nil {
		a.d.Log.Warn("publish metrics", "error", err)
	}
}

// p2pRefused reads the p2p part's counters per signature.
func p2pRefused(p netstate.P2P, counters map[string]uint64) map[string]uint64 {
	if !p.Active() {
		return nil
	}
	out := map[string]uint64{}
	for _, s := range p.Signatures {
		out[s.Name] += counters[s.Counter]
	}
	return out
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
