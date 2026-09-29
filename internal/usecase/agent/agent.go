// Package agent is the node agent's control loop (ТЗ §7): it keeps the kernel
// holding the state the policy asks for, the exits alive and the lists fresh.
package agent

import (
	"context"
	"log/slog"
	"net/netip"
	"slices"
	"time"

	"github.com/lib4u/vnm/internal/domain/netstate"
	"github.com/lib4u/vnm/internal/domain/policy"
	"github.com/lib4u/vnm/internal/usecase/lists"
)

// Intervals are the loop's cadences (ТЗ §4, §7.4). Zero fields take the
// defaults; tests shorten them.
type Intervals struct {
	// Check is how often exits are checked and the state reconciled.
	Check time.Duration
	// Refresh is how often the local copies of remote lists are checked for
	// being due. Each list sets how old its copies may get (guard ТЗ §3.1); a
	// failed download stays due and is retried at this cadence.
	Refresh time.Duration
}

// DefaultIntervals are the production cadences.
var DefaultIntervals = Intervals{
	Check:   15 * time.Second,
	Refresh: 10 * time.Minute,
}

// StaleAfter is how old the last pass may be before the agent counts as
// stuck: four checks missed in a row.
var StaleAfter = 4 * DefaultIntervals.Check

func (i Intervals) withDefaults() Intervals {
	d := DefaultIntervals
	if i.Check > 0 {
		d.Check = i.Check
	}
	if i.Refresh > 0 {
		d.Refresh = i.Refresh
	}
	return d
}

// Deps are the agent's collaborators.
type Deps struct {
	Config    ConfigSource
	Kernel    Kernel
	Store     Store
	Counters  Counters
	Exits     ExitChecker
	Lists     ListResolver
	Resolver  Resolver
	Refresher ListRefresher
	Uplinks   Uplinks
	Listening Listening
	Lock      Locker
	Metrics   Metrics
	Log       *slog.Logger
	Now       func() time.Time
	Intervals Intervals
}

// Agent is the control loop's state. It is touched only by the loop's
// goroutine; a list refresh runs beside it but only calls the Refresher.
type Agent struct {
	d  Deps
	iv Intervals

	cfg     policy.Config
	version string

	// ranges and domains are the resolved lists, rangesFor the policy
	// version they were resolved for — a policy is planned only with its own
	// lists, never with another policy's — and rangeDefs the definition each
	// list had then. stale means the local copies changed since, whoever
	// refreshed them: the agent or `vnm lists update`.
	ranges    map[string][]netip.Prefix
	domains   map[string][]string
	rangesFor string
	rangeDefs map[string]policy.List
	stale     bool
	// listsCurrent is false while the lists in force are older than the
	// copies, because the copies did not resolve.
	listsCurrent bool
	// failed names the guard lists whose last resolution failed.
	failed map[string]bool
	// copies are the local copies of the sources as of the last pass: a
	// change marks the lists stale.
	copies map[string]lists.Copy
	// refreshWanted asks the loop for a download now: the policy started
	// reading a source it had not read before.
	refreshWanted bool

	// applied is the state the kernel is taken to hold: the last one this
	// process applied, or, after a restart, the last good one on disk — the
	// reference for bounds, health and the exits to retire, even while the
	// policy cannot be planned.
	applied *netstate.State
	// started is set once the last good state was read.
	started bool
	// trusted means this process saw the kernel hold applied; before that,
	// a difference is a restart catching up, not drift.
	trusted bool
	// healthSynced means the kernel holds applied.Health. It is false after a
	// restart and after a failed apply, whose rollback leaves a health
	// nobody computed.
	healthSynced bool
	// resolverSynced means the resolver serves applied.
	resolverSynced bool
	// retire are the interfaces of exits the last good state had and the
	// policy no longer has; they are removed until that succeeds.
	retire []string
	// policyErr is why the last pass did not bring the kernel to the policy.
	policyErr error
	// counters are the last counters read, published again when a read fails:
	// a gap would look like a counter reset.
	counters map[string]uint64

	applyErrors uint64
	drift       uint64
}

// New returns an Agent.
func New(d Deps) *Agent {
	return &Agent{d: d, iv: d.Intervals.withDefaults(), listsCurrent: true}
}

// Run reconciles at once, then every check interval, and refreshes lists in
// the background until ctx ends. A download of tens of megabytes must not stop
// exit checks: an exit dying meanwhile would blackhole its traffic instead of
// refusing it.
func (a *Agent) Run(ctx context.Context) error {
	check := time.NewTicker(a.iv.Check)
	defer check.Stop()
	refresh := time.NewTimer(0)
	defer refresh.Stop()

	done := make(chan error, 1)
	refreshing := false
	startRefresh := func() bool {
		if refreshing || (a.version == "" && !a.loadConfig()) {
			return false
		}
		refreshing = true
		cfg := a.cfg
		go func() { done <- a.d.Refresher.Refresh(ctx, cfg) }()
		return true
	}
	// A download the policy asks for starts as soon as none is running.
	startWanted := func() {
		if a.refreshWanted && startRefresh() {
			a.refreshWanted = false
		}
	}

	a.Reconcile(ctx)
	for {
		select {
		case <-ctx.Done():
			if refreshing {
				<-done
			}
			return nil
		case <-check.C:
			a.Reconcile(ctx)
			startWanted()
		case <-refresh.C:
			startRefresh()
			refresh.Reset(a.iv.Refresh)
		case err := <-done:
			refreshing = false
			if err != nil {
				a.d.Log.Warn("list refresh failed, previous copies stay and are retried", "error", err)
			}
			a.Reconcile(ctx)
			startWanted()
		}
	}
}

// Reconcile runs one pass. Every failure is logged here and nowhere else; the
// loop goes on, and the kernel keeps the last state that was applied.
func (a *Agent) Reconcile(ctx context.Context) {
	release, err := a.d.Lock.Lock(ctx)
	if err != nil {
		a.d.Log.Warn("state is being changed by another vnm process, pass skipped", "error", err)
		return
	}
	defer func() {
		if err := release(); err != nil {
			a.d.Log.Error("release state lock", "error", err)
		}
	}()

	a.start()
	valid := a.loadConfig()
	if a.version == "" {
		a.publish(ctx, valid, nil)
		return
	}
	a.checkLists()
	statuses, err := a.d.Exits.Check(ctx, a.cfg)
	if err != nil {
		a.d.Log.Warn("exit check", "error", err)
	}
	for _, st := range statuses {
		if st.Changed {
			a.d.Log.Info("exit health changed", "exit", st.Name, "healthy", st.Healthy)
		}
		if st.Renewed {
			a.d.Log.Warn("exit renew command ran: no handshake for long", "exit", st.Name, "recreated", st.Recreated)
		}
	}
	a.retireExits(ctx)
	a.policyErr = a.converge(ctx, statuses)
	if a.policyErr != nil && ctx.Err() == nil {
		// A pass cut short by shutdown is not a failure worth an error line.
		a.d.Log.Error("reconcile", "error", a.policyErr)
	}
	a.publish(ctx, valid, statuses)
}

// start takes the last good state as the applied one, once: a restarted agent
// keeps the bounds of the lists in force (ТЗ §7.4), keeps refusing dead exits
// while the policy cannot be planned (I-2), and removes the interfaces of
// exits that left the policy while it was down.
func (a *Agent) start() {
	if a.started {
		return
	}
	a.started = true
	last, ok, err := a.d.Store.LastGood()
	switch {
	case err != nil:
		a.d.Log.Error("last good state unreadable, starting from nothing", "error", err)
		return
	case !ok:
		return
	}
	a.applied = &last
	for _, e := range last.Classify.Exits {
		a.retire = append(a.retire, e.Iface)
	}
}

// retireExits removes the interfaces of exits that are no longer in the
// policy; an interface an exit of the policy uses is not the agent's to
// remove, and the supervisor tracks it.
func (a *Agent) retireExits(ctx context.Context) {
	a.retire = slices.DeleteFunc(a.retire, func(iface string) bool {
		if slices.ContainsFunc(a.cfg.Exits, func(e policy.Exit) bool { return e.Iface == iface }) {
			return true
		}
		if err := a.d.Exits.Retire(ctx, iface); err != nil {
			a.d.Log.Warn("remove the interface of a retired exit", "iface", iface, "error", err)
			return false
		}
		a.d.Log.Info("interface of a retired exit removed", "iface", iface)
		return true
	})
}

// loadConfig reads the policy. A bad file keeps the last valid policy in
// force and is reported, never applied partially (ТЗ §7.3). A policy that
// reads a source the previous one did not asks for a download at once rather
// than waiting a day for it.
func (a *Agent) loadConfig() bool {
	cfg, version, err := a.d.Config.Load()
	if err != nil {
		a.d.Log.Error("config is invalid, the last valid one stays in force", "error", err)
		return false
	}
	if version == a.version {
		return true
	}
	for _, u := range cfg.RemoteURLs() {
		if !slices.Contains(a.cfg.RemoteURLs(), u) {
			a.refreshWanted = true
		}
	}
	a.cfg, a.version = cfg, version
	return true
}
