package exits_test

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/lib4u/vnm/internal/domain/policy"
	"github.com/lib4u/vnm/internal/testsupport"
	"github.com/lib4u/vnm/internal/usecase/exits"
)

// device fakes exit interfaces: up and handshaking unless told otherwise.
type device struct {
	up        map[string]bool
	readErr   error
	calls     []string
	endpoints []netip.AddrPort
	// current is the endpoint the interface uses; ensured is what Ensure set.
	current netip.AddrPort
	ensured []netip.AddrPort
	// removeFails fails the next removals.
	removeFails int
	// silent means no handshake at all.
	silent bool
}

func newDevice() *device { return &device{up: map[string]bool{}} }

func (d *device) State(_ context.Context, e policy.Exit) (exits.LinkState, error) {
	if d.readErr != nil {
		return exits.LinkState{}, d.readErr
	}
	if !d.up[e.Iface] {
		return exits.LinkState{}, nil
	}
	if d.silent {
		return exits.LinkState{Up: true, Endpoint: d.current}, nil
	}
	return exits.LinkState{Up: true, HandshakeAge: 20 * time.Second, Endpoint: d.current}, nil
}

func (d *device) Ensure(_ context.Context, _ policy.Exit, ep netip.AddrPort) error {
	d.ensured = append(d.ensured, ep)
	return nil
}

func (d *device) ResetPeer(_ context.Context, _ policy.Exit, ep netip.AddrPort) error {
	d.calls = append(d.calls, "reset")
	d.endpoints = append(d.endpoints, ep)
	return nil
}

func (d *device) Recreate(_ context.Context, e policy.Exit, _ netip.AddrPort) error {
	d.calls = append(d.calls, "recreate")
	d.up[e.Iface] = true
	return nil
}

func (d *device) Remove(_ context.Context, iface string) error {
	d.calls = append(d.calls, "remove "+iface)
	if d.removeFails > 0 {
		d.removeFails--
		return errors.New("netlink: busy")
	}
	delete(d.up, iface)
	return nil
}

// prober passes or fails every probe, or cannot make it at all.
type prober struct{ ok, unknown bool }

func (p *prober) Probe(context.Context, policy.Exit) error {
	switch {
	case p.unknown:
		return fmt.Errorf("%w: resolver down", exits.ErrProbeUnknown)
	case p.ok:
		return nil
	}
	return errors.New("no answer")
}

// renewer counts renewals.
type renewer struct {
	runs int
	err  error
}

func (r *renewer) Renew(context.Context, policy.Exit) error {
	r.runs++
	return r.err
}

type rig struct {
	dev   *device
	renew *renewer
	probe *prober
	sup   *exits.Supervisor
	cfg   policy.Config
	now   time.Time
}

func newRig() *rig {
	r := &rig{dev: newDevice(), renew: &renewer{}, probe: &prober{ok: true}, cfg: testsupport.Policy(), now: time.Unix(0, 0)}
	r.cfg.Exits[0].Endpoints = []netip.AddrPort{
		netip.MustParseAddrPort("162.159.192.1:2408"),
		netip.MustParseAddrPort("162.159.192.1:500"),
	}
	r.sup = exits.NewSupervisor(r.dev, r.probe, r.renew, func() time.Time { return r.now })
	return r
}

func (r *rig) check(t *testing.T) exits.Status {
	t.Helper()
	r.now = r.now.Add(15 * time.Second)
	st, err := r.sup.Check(context.Background(), r.cfg)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	return st[0]
}

// On a fresh node the interface does not exist: the first check creates it —
// that check is a failure — and the exit becomes healthy only after four
// passing checks of its own.
func TestFreshNodeCreatesExitThenTrustsIt(t *testing.T) {
	r := newRig()
	st := r.check(t)
	if !st.Present || st.Healthy || !slices.Equal(r.dev.calls, []string{"recreate"}) {
		t.Fatalf("first check: %+v, calls %v", st, r.dev.calls)
	}
	for range 3 {
		if st = r.check(t); st.Healthy {
			t.Fatalf("healthy before four passing checks: %+v", st)
		}
	}
	if st = r.check(t); !st.Healthy || !st.Changed {
		t.Fatalf("after four passing checks: %+v", st)
	}
}

// An agent restart over a working tunnel must not refuse its traffic while
// the exit "proves itself" again: found running and passing, it is healthy on
// the first check. Found on the pilot node: every restart cost ~45 s of RU
// traffic refused.
func TestRestartOverWorkingExitKeepsItHealthy(t *testing.T) {
	r := newRig()
	r.dev.up["warp"] = true // the interface outlived the previous agent
	if st := r.check(t); !st.Healthy || !st.Present {
		t.Fatalf("first check over a running exit: %+v", st)
	}
	if len(r.dev.calls) != 0 {
		t.Fatalf("a working exit was touched: %v", r.dev.calls)
	}
}

func TestDeadExitClimbsLadderAcrossEndpoints(t *testing.T) {
	r := newRig()
	r.dev.up["warp"] = true
	for range 4 {
		r.check(t)
	}
	r.probe.ok = false
	for range 15 {
		r.check(t)
	}
	if want := []string{"reset", "reset", "recreate", "reset", "reset"}; !slices.Equal(r.dev.calls, want) {
		t.Fatalf("calls = %v, want %v", r.dev.calls, want)
	}
	// Resets 2 and 4 are endpoint switches; with two endpoints the second
	// round comes back to the first.
	eps := r.cfg.Exits[0].Endpoints
	if want := []netip.AddrPort{eps[0], eps[1], eps[1], eps[0]}; !slices.Equal(r.dev.endpoints, want) {
		t.Fatalf("endpoints = %v, want %v", r.dev.endpoints, want)
	}
}

// A failed state read keeps the previous verdict instead of treating the exit
// as gone: recreating a live tunnel on a netlink hiccup would cut it for
// nothing.
func TestReadErrorKeepsVerdict(t *testing.T) {
	r := newRig()
	r.dev.up["warp"] = true
	for range 4 {
		r.check(t)
	}
	r.dev.readErr = errors.New("netlink: resource busy")
	r.now = r.now.Add(15 * time.Second)
	st, err := r.sup.Check(context.Background(), r.cfg)
	if err == nil || !st[0].Healthy || slices.Contains(r.dev.calls, "recreate") {
		t.Fatalf("status %+v err %v calls %v", st[0], err, r.dev.calls)
	}
}

func TestExitRemovedFromPolicyLosesItsInterface(t *testing.T) {
	r := newRig()
	r.check(t)
	r.cfg.Exits = nil
	r.cfg.Rules = nil
	if _, err := r.sup.Check(context.Background(), r.cfg); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(r.dev.calls, "remove warp") {
		t.Fatalf("calls = %v, want the interface removed", r.dev.calls)
	}
}

func TestStatusesInSlotOrder(t *testing.T) {
	r := newRig()
	second := r.cfg.Exits[0]
	second.Name, second.Iface, second.Slot = "wg2", "wg2", 1
	r.cfg.Exits = []policy.Exit{second, r.cfg.Exits[0]}
	st, err := r.sup.Check(context.Background(), r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	got := fmt.Sprint(st[0].Slot, st[1].Slot)
	if got != "0 1" {
		t.Fatalf("slots = %s, want 0 1", got)
	}
}

// An interface that outlived the previous agent keeps the endpoint it found
// working; moving it back to the first would reset a live tunnel.
func TestRestartKeepsTheEndpointInUse(t *testing.T) {
	r := newRig()
	r.dev.up["warp"] = true
	r.dev.current = r.cfg.Exits[0].Endpoints[1]
	if st := r.check(t); !st.Healthy {
		t.Fatalf("status = %+v", st)
	}
	if !slices.Equal(r.dev.ensured, []netip.AddrPort{r.cfg.Exits[0].Endpoints[1]}) {
		t.Fatalf("ensured %v, want the endpoint in use", r.dev.ensured)
	}
}

// A probe that could not be made says nothing: the verdict stays, and it is
// not reported as a change.
func TestUnknownProbeKeepsVerdict(t *testing.T) {
	r := newRig()
	r.dev.up["warp"] = true
	if st := r.check(t); !st.Healthy || !st.Changed {
		t.Fatalf("first check: %+v", st)
	}
	r.probe.unknown = true
	for range 5 {
		r.now = r.now.Add(15 * time.Second)
		st, err := r.sup.Check(context.Background(), r.cfg)
		if !errors.Is(err, exits.ErrProbeUnknown) || !st[0].Healthy || st[0].Changed {
			t.Fatalf("status %+v err %v", st[0], err)
		}
	}
	if len(r.dev.calls) != 0 {
		t.Fatalf("recovered an exit nobody could probe: %v", r.dev.calls)
	}
}

// An exit renamed while the old interface cannot be removed keeps that
// interface on the list until it goes, even though the exit of the same name
// already tracks the new one.
func TestRenamedExitOldInterfaceIsRetried(t *testing.T) {
	r := newRig()
	r.dev.up["warp"] = true
	r.check(t)
	r.cfg.Exits[0].Iface = "warp2"
	r.dev.removeFails = 1
	r.now = r.now.Add(15 * time.Second)
	if _, err := r.sup.Check(context.Background(), r.cfg); err == nil {
		t.Fatal("a failed removal was not reported")
	}
	r.check(t)
	if _, up := r.dev.up["warp"]; up {
		t.Fatalf("the old interface stayed: calls %v", r.dev.calls)
	}
}

// An exit with no handshake for its After gets new credentials, then a new
// interface — at most once per Every.
func TestRenewAfterLongSilence(t *testing.T) {
	r := newRig()
	r.cfg.Exits[0].Renew = &policy.Renew{Command: []string{"/usr/local/bin/vnm", "warp", "reissue"}, After: 15 * time.Minute, Every: time.Hour}
	r.dev.up["warp"], r.dev.silent, r.probe.ok = true, true, false
	step := func(d time.Duration) (renewed bool) {
		for end := r.now.Add(d); r.now.Before(end); {
			r.now = r.now.Add(15 * time.Second)
			st, _ := r.sup.Check(context.Background(), r.cfg)
			renewed = renewed || st[0].Renewed
		}
		return renewed
	}
	if step(14 * time.Minute) {
		t.Fatal("renewed before the silence lasted After")
	}
	calls := len(r.dev.calls)
	if !step(2*time.Minute) || r.renew.runs != 1 {
		t.Fatalf("renewals = %d after After", r.renew.runs)
	}
	if !slices.Contains(r.dev.calls[calls:], "recreate") {
		t.Fatalf("no new interface after the renewal: %v", r.dev.calls[calls:])
	}
	if step(40*time.Minute) || r.renew.runs != 1 {
		t.Fatalf("renewals = %d within Every", r.renew.runs)
	}
	if !step(30*time.Minute) || r.renew.runs != 2 {
		t.Fatalf("renewals = %d after Every", r.renew.runs)
	}
}

// A live handshake means the credentials work: whatever else fails, a new
// registration would not help.
func TestNoRenewWhileHandshaking(t *testing.T) {
	r := newRig()
	r.cfg.Exits[0].Renew = &policy.Renew{Command: []string{"/usr/local/bin/vnm", "warp", "reissue"}, After: 15 * time.Minute, Every: time.Hour}
	r.dev.up["warp"], r.probe.ok = true, false
	for range 200 {
		r.now = r.now.Add(15 * time.Second)
		_, _ = r.sup.Check(context.Background(), r.cfg)
	}
	if r.renew.runs != 0 {
		t.Fatalf("renewed %d times with a live handshake", r.renew.runs)
	}
}
