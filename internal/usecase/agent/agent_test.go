package agent_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/lib4u/vnm/internal/domain/netstate"
	"github.com/lib4u/vnm/internal/domain/policy"
	"github.com/lib4u/vnm/internal/testsupport"
	"github.com/lib4u/vnm/internal/usecase/agent"
	"github.com/lib4u/vnm/internal/usecase/apply"
	"github.com/lib4u/vnm/internal/usecase/exits"
	"github.com/lib4u/vnm/internal/usecase/lists"
)

type configSource struct {
	cfg     policy.Config
	version string
	err     error
}

func (c *configSource) Load() (policy.Config, string, error) { return c.cfg, c.version, c.err }

type kernel struct {
	applies     []netstate.State
	health      []netstate.Health
	verifyErr   error
	applyErr    error
	countersErr error
}

func (k *kernel) Apply(_ context.Context, s netstate.State) error {
	if k.applyErr != nil {
		return k.applyErr
	}
	k.applies = append(k.applies, s)
	return nil
}
func (k *kernel) Verify(context.Context, netstate.State) error { return k.verifyErr }
func (k *kernel) SetHealth(_ context.Context, h netstate.Health) error {
	k.health = append(k.health, h)
	return nil
}
func (k *kernel) Counters(context.Context) (map[string]uint64, error) {
	if k.countersErr != nil {
		return nil, k.countersErr
	}
	return map[string]uint64{"r0_ru_ip_4": 7, "g_scanners_4": 3, "g_scanners_6": 2}, nil
}

type exitChecker struct {
	healthy   bool
	recreated bool
	retired   []string
}

func (e *exitChecker) Check(context.Context, policy.Config) ([]exits.Status, error) {
	return []exits.Status{{Name: "warp", Slot: 0, Present: true, Healthy: e.healthy, Recreated: e.recreated}}, nil
}

func (e *exitChecker) Retire(_ context.Context, iface string) error {
	e.retired = append(e.retired, iface)
	return nil
}

// store holds the last good state a previous agent left.
type store struct {
	last netstate.State
	ok   bool
}

func (s *store) LastGood() (netstate.State, bool, error) { return s.last, s.ok, nil }

type resolver struct {
	ranges   []netip.Prefix
	err      error
	guardErr error
	calls    int
	previous map[string]lists.Sizes
}

func (r *resolver) Domains(context.Context, policy.Config) (map[string][]string, error) {
	return map[string][]string{"ru_suffix": {"ru", "xn--p1ai"}}, nil
}

// dns records what the resolver was asked to serve.
type dns struct {
	applied  []netstate.DNSState
	down     bool
	noUser   bool
	applyErr error
}

func (d *dns) Up(context.Context, uint16) bool { return !d.down }

func (d *dns) UID() (uint32, error) {
	if d.noUser {
		return 0, errors.New("unknown user vnm-dns")
	}
	return 997, nil
}

func (d *dns) Apply(_ context.Context, s netstate.State) error {
	d.applied = append(d.applied, s.DNS)
	return d.applyErr
}

func (r *resolver) Resolve(_ context.Context, cfg policy.Config, previous map[string]lists.Sizes) (lists.Resolved, error) {
	r.calls++
	r.previous = previous
	if r.err != nil {
		return lists.Resolved{}, r.err
	}
	out := lists.Resolved{Ranges: map[string][]netip.Prefix{}, Failed: map[string]error{}}
	uses := cfg.ListUses()
	if uses["ru_ip"].Egress {
		out.Ranges["ru_ip"] = r.ranges
	}
	if uses["scanners"].Guard {
		if r.guardErr != nil {
			out.Failed["scanners"] = r.guardErr
		} else {
			out.Ranges["scanners"] = testsupport.ScannerRanges
		}
	}
	return out, nil
}

// refresher counts refreshes; block, when set, holds each one until closed.
type refresher struct {
	mu      sync.Mutex
	updated time.Time
	// modified is when the content changed; zero means with updated.
	modified  time.Time
	missing   bool
	refreshes int
	block     chan struct{}
}

func (r *refresher) Refresh(ctx context.Context, _ policy.Config) error {
	r.mu.Lock()
	r.refreshes++
	block := r.block
	r.mu.Unlock()
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
		}
	}
	return nil
}

func (r *refresher) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.refreshes
}

func (r *refresher) Copies(cfg policy.Config) map[string]lists.Copy {
	out := map[string]lists.Copy{}
	for _, u := range cfg.RemoteURLs() {
		modified := r.modified
		if modified.IsZero() {
			modified = r.updated
		}
		out[u] = lists.Copy{Updated: r.updated, Modified: modified, Missing: r.missing}
	}
	return out
}

// host fakes the uplink and the listening ports.
type host struct{}

func (host) Uplinks(context.Context) ([]string, error) { return []string{"ens3"}, nil }
func (host) Listening() (netstate.Ports, error)        { return netstate.Ports{TCP: []uint16{22}}, nil }

type locker struct{ busy bool }

func (l *locker) Lock(context.Context) (func() error, error) {
	if l.busy {
		return nil, errors.New("busy")
	}
	return func() error { return nil }, nil
}

type metrics struct {
	mu     sync.Mutex
	last   agent.Snapshot
	passes int
}

func (m *metrics) Publish(s agent.Snapshot) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.last = s
	m.passes++
	return nil
}

func (m *metrics) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.passes
}

type rig struct {
	cfg     *configSource
	store   *store
	kernel  *kernel
	exits   *exitChecker
	lists   *resolver
	ref     *refresher
	lock    *locker
	dns     *dns
	metrics *metrics
	agent   *agent.Agent
	now     time.Time
}

func newRig() *rig {
	r := &rig{
		cfg:     &configSource{cfg: testsupport.Policy(), version: "v1"},
		store:   &store{},
		kernel:  &kernel{},
		exits:   &exitChecker{healthy: true},
		lists:   &resolver{ranges: testsupport.RURanges},
		lock:    &locker{},
		dns:     &dns{},
		metrics: &metrics{},
		now:     time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC),
	}
	r.ref = &refresher{updated: r.now.Add(-50 * time.Hour)}
	r.build("v1")
	return r
}

// build starts the rig's agent anew as the given build, with the rig's parts.
func (r *rig) build(version string) {
	r.agent = agent.New(agent.Deps{
		Build:  version,
		Config: r.cfg, Kernel: r.kernel, Store: r.store, Counters: r.kernel, Exits: r.exits,
		Lists: r.lists, Resolver: r.dns, Refresher: r.ref, Uplinks: host{}, Listening: host{},
		Lock: r.lock, Metrics: r.metrics,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now: func() time.Time { return r.now },
		Intervals: agent.Intervals{
			Check: 5 * time.Millisecond, Refresh: time.Hour,
		},
	})
}

// run runs the loop until cond holds or a second passes.
func (r *rig) run(t *testing.T, cond func() bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() { _ = r.agent.Run(ctx); close(done) }()
	for !cond() {
		select {
		case <-ctx.Done():
			<-done
			t.Fatal("condition not reached")
		case <-time.After(time.Millisecond):
		}
	}
	cancel()
	<-done
}

func (r *rig) pass() { r.agent.Reconcile(context.Background()) }

func TestFirstPassAppliesThenNothingChanges(t *testing.T) {
	r := newRig()
	r.pass()
	if len(r.kernel.applies) != 1 {
		t.Fatalf("first pass: %d applies", len(r.kernel.applies))
	}
	r.pass()
	r.pass()
	// Rewriting a 25 000-element table every 15 s would reset its counters
	// and its resolver-filled sets for nothing.
	if len(r.kernel.applies) != 1 || len(r.kernel.health) != 0 || r.lists.calls != 1 {
		t.Fatalf("idle passes: applies %d, health %d, resolves %d", len(r.kernel.applies), len(r.kernel.health), r.lists.calls)
	}
}

// A health change touches only the dead set.
func TestHealthChangeSetsDeadSetOnly(t *testing.T) {
	r := newRig()
	r.pass()
	r.exits.healthy = false
	r.pass()
	if len(r.kernel.applies) != 1 {
		t.Fatalf("health change rewrote the table: %d applies", len(r.kernel.applies))
	}
	if len(r.kernel.health) != 1 || !slices.Equal(r.kernel.health[0].DeadSlots, []int{0}) {
		t.Fatalf("dead sets = %v, want [[0]]", r.kernel.health)
	}
}

func TestDriftIsRepaired(t *testing.T) {
	r := newRig()
	r.pass()
	r.kernel.verifyErr = apply.ErrDiverged
	r.pass()
	if len(r.kernel.applies) != 2 || r.metrics.last.Drift != 1 {
		t.Fatalf("applies %d, drift %d", len(r.kernel.applies), r.metrics.last.Drift)
	}
}

// A broken config keeps the last valid policy in force; nothing is applied
// from it, and monitoring sees it.
func TestInvalidConfigKeepsLastValid(t *testing.T) {
	r := newRig()
	r.pass()
	r.cfg.err, r.cfg.version = policy.ErrInvalid, "v2"
	r.pass()
	if len(r.kernel.applies) != 1 {
		t.Fatalf("applies = %d, want the first only", len(r.kernel.applies))
	}
	if r.metrics.last.ConfigValid {
		t.Fatal("metrics report a valid config")
	}
}

func TestConfigChangeReplans(t *testing.T) {
	r := newRig()
	r.pass()
	r.cfg.cfg.Mode, r.cfg.version = policy.ModeObserve, "v2"
	r.pass()
	if len(r.kernel.applies) != 2 || !r.kernel.applies[1].Classify.Observe || r.lists.calls != 2 {
		t.Fatalf("applies %d, resolves %d", len(r.kernel.applies), r.lists.calls)
	}
}

func TestBusyLockSkipsPass(t *testing.T) {
	r := newRig()
	r.lock.busy = true
	r.pass()
	if len(r.kernel.applies) != 0 {
		t.Fatal("applied without the lock")
	}
}

func TestRunRefreshesWhenPolicyAddsSource(t *testing.T) {
	r := newRig()
	r.run(t, func() bool { return r.ref.count() >= 1 && r.metrics.count() >= 2 })
	before := r.ref.count()

	r.cfg.cfg.Lists = append(r.cfg.cfg.Lists, policy.List{
		Name: "extra", IP: []policy.Source{{Kind: policy.SourceURL, Value: "https://example.org/ru.txt"}}, Bounds: policy.DefaultBounds,
	})
	r.cfg.version = "v2"
	r.run(t, func() bool { return r.ref.count() > before })
}

// A slow download must not stop the checks: an exit dying meanwhile would
// blackhole its traffic instead of refusing it.
func TestRunKeepsCheckingDuringRefresh(t *testing.T) {
	r := newRig()
	r.ref.block = make(chan struct{})
	defer close(r.ref.block)
	r.run(t, func() bool { return r.ref.count() == 1 && r.metrics.count() >= 5 })
}

// The resolver follows every applied state: it serves the domain sets of the
// policy in force, and nothing once the policy is off.
func TestResolverFollowsAppliedState(t *testing.T) {
	r := newRig()
	r.pass()
	if len(r.dns.applied) != 1 || !r.dns.applied[0].Enabled() {
		t.Fatalf("resolver after the first apply: %+v", r.dns.applied)
	}
	r.cfg.cfg.Mode, r.cfg.version = policy.ModeOff, "v2"
	r.pass()
	if last := r.dns.applied[len(r.dns.applied)-1]; last.Enabled() {
		t.Fatalf("resolver still serving with the policy off: %+v", last)
	}
}

// DNS goes to the resolver only while it answers: its death turns the
// redirect off through the health alone, and its return turns it back on.
func TestResolverHealthGatesRedirect(t *testing.T) {
	r := newRig()
	r.pass()
	if got := r.kernel.applies[0]; !got.Health.ResolverUp || got.Classify.ResolverUID != 997 {
		t.Fatalf("first apply: resolver up %t uid %d", got.Health.ResolverUp, got.Classify.ResolverUID)
	}
	r.dns.down = true
	r.pass()
	r.dns.down = false
	r.pass()
	if len(r.kernel.applies) != 1 {
		t.Fatalf("resolver health rewrote the table: %d applies", len(r.kernel.applies))
	}
	if len(r.kernel.health) != 2 || r.kernel.health[0].ResolverUp || !r.kernel.health[1].ResolverUp {
		t.Fatalf("health = %+v, want resolver down then up", r.kernel.health)
	}
}

// Without the resolver's user the host redirect cannot let the resolver's own
// queries out, so a policy with domain lists is not applied at all.
func TestUnknownResolverUserRefusesPolicy(t *testing.T) {
	r := newRig()
	r.dns.noUser = true
	r.pass()
	if len(r.kernel.applies) != 0 {
		t.Fatalf("policy applied without the resolver's user: %+v", r.kernel.applies)
	}
}

func TestSnapshot(t *testing.T) {
	r := newRig()
	r.pass()
	s := r.metrics.last
	ruIP := s.Lists["ru_ip"]
	if !s.ConfigValid || ruIP.Age != 50*time.Hour || ruIP.Entries != len(testsupport.RURanges) || s.Counters["r0_ru_ip_4"] != 7 {
		t.Fatalf("snapshot = %+v", s)
	}
	if ruIP.Refresh != policy.DefaultRefresh || s.Lists["scanners"].Refresh != 0 {
		t.Fatalf("refresh: %+v", s.Lists)
	}
	if s.Guard.Mode != policy.ModeEnforce || s.Guard.Refused["scanners"] != 5 {
		t.Fatalf("guard = %+v", s.Guard)
	}
}
