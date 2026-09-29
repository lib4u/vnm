package exits

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/lib4u/vnm/internal/domain/policy"
)

// LinkState is what the kernel says about an exit's interface.
type LinkState struct {
	Up bool
	// HandshakeAge is the age of the last handshake; zero means none yet.
	HandshakeAge time.Duration
	// Endpoint is the peer endpoint the interface uses now; zero when none.
	Endpoint netip.AddrPort
}

// ErrProbeUnknown means a probe could not be made at all — the probe host
// could not be resolved — so it says nothing about the exit: the verdict
// stays as it was.
var ErrProbeUnknown = errors.New("probe could not be made")

// Device controls exit interfaces.
type Device interface {
	State(ctx context.Context, e policy.Exit) (LinkState, error)
	// Ensure makes an existing interface match the exit's config and endpoint.
	Ensure(ctx context.Context, e policy.Exit, endpoint netip.AddrPort) error
	// ResetPeer re-applies the peer at endpoint, forcing a new handshake.
	ResetPeer(ctx context.Context, e policy.Exit, endpoint netip.AddrPort) error
	// Recreate deletes the interface, if any, and creates it from the config.
	Recreate(ctx context.Context, e policy.Exit, endpoint netip.AddrPort) error
	// Remove deletes an interface; a missing one is not an error.
	Remove(ctx context.Context, iface string) error
}

// Renewer runs an exit's renew command: new credentials, a rewritten config.
type Renewer interface {
	Renew(ctx context.Context, e policy.Exit) error
}

// staleHandshake is how old a WireGuard handshake may be while the tunnel
// lives: a peer rekeys every two minutes.
const staleHandshake = 3 * time.Minute

// Prober checks that traffic gets through an exit.
type Prober interface {
	Probe(ctx context.Context, e policy.Exit) error
}

// Status is an exit's state after a check.
type Status struct {
	Name string
	Slot int
	// Present means the interface exists, so it can carry a route.
	Present bool
	Healthy bool
	Changed bool
	Alert   bool
	// Recreated means this check recreated the interface — and with it
	// dropped the routes through it, which the next apply puts back.
	Recreated bool
	// Renewed means this check ran the exit's renew command.
	Renewed bool
}

// Supervisor checks and heals every exit of the policy.
type Supervisor struct {
	dev   Device
	probe Prober
	renew Renewer
	now   func() time.Time
	exits map[string]*tracked
	// retiring are interfaces of dropped exits whose removal failed.
	retiring []string
}

type tracked struct {
	exit     policy.Exit
	monitor  Monitor
	endpoint int
	last     Status
	// checked is false until the first check of this exit by this process.
	checked bool
	// handshook is when the exit last had a fresh handshake — or, until it
	// has one, when this process started tracking it.
	handshook time.Time
	// renewed is when its renew command last ran.
	renewed time.Time
}

// NewSupervisor returns a Supervisor. now is the clock, injected for tests.
func NewSupervisor(dev Device, probe Prober, renew Renewer, now func() time.Time) *Supervisor {
	return &Supervisor{dev: dev, probe: probe, renew: renew, now: now, exits: map[string]*tracked{}}
}

// Check runs one health check of every exit, performs the recovery actions due
// and returns the exits' statuses in slot order. Errors of individual exits are
// returned together; they never stop the other exits' checks.
func (s *Supervisor) Check(ctx context.Context, cfg policy.Config) ([]Status, error) {
	var errs []error
	errs = append(errs, s.forget(ctx, cfg)...)

	exits := cfg.ExitsBySlot()
	statuses := make([]Status, 0, len(exits))
	for _, e := range exits {
		st, err := s.check(ctx, e)
		if err != nil {
			errs = append(errs, fmt.Errorf("exit %q: %w", e.Name, err))
		}
		statuses = append(statuses, st)
	}
	return statuses, errors.Join(errs...)
}

// forget stops tracking exits gone from the policy and removes their
// interfaces: they belong to the agent, and nothing else will remove them.
//
// An interface whose removal failed is kept to be removed on the next checks:
// the exit of the same name may already track a new interface.
func (s *Supervisor) forget(ctx context.Context, cfg policy.Config) []error {
	for name, t := range s.exits {
		if e, ok := cfg.Exit(name); ok && e.Iface == t.exit.Iface {
			continue
		}
		s.retiring = append(s.retiring, t.exit.Iface)
		delete(s.exits, name)
	}
	var errs []error
	s.retiring = slices.DeleteFunc(s.retiring, func(iface string) bool {
		if err := s.dev.Remove(ctx, iface); err != nil {
			errs = append(errs, fmt.Errorf("remove interface %s of a dropped exit: %w", iface, err))
			return false
		}
		return true
	})
	return errs
}

func (s *Supervisor) check(ctx context.Context, e policy.Exit) (Status, error) {
	t := s.track(e)
	state, err := s.dev.State(ctx, e)
	if err != nil {
		// Not knowing is not the same as down: recreating a live tunnel on a
		// failed netlink read would cut it for nothing. The verdict stays.
		return t.unchanged(), fmt.Errorf("read state: %w", err)
	}
	if !t.checked {
		// An interface that outlived the previous agent keeps the endpoint it
		// found working: moving it back to the first one would reset a live
		// tunnel, and the first one may be the port the hoster drops.
		t.adoptEndpoint(state.Endpoint)
	}

	var errs []error
	probeOK := false
	if state.Up {
		if err := s.dev.Ensure(ctx, e, t.currentEndpoint()); err != nil {
			errs = append(errs, fmt.Errorf("ensure: %w", err))
		}
		err := s.probe.Probe(ctx, e)
		if errors.Is(err, ErrProbeUnknown) {
			return t.unchanged(), errors.Join(append(errs, err)...)
		}
		probeOK = err == nil
	}

	check := Check{LinkUp: state.Up, HandshakeAge: state.HandshakeAge, ProbeOK: probeOK}
	var v Verdict
	if !t.checked && state.Up {
		v = t.monitor.Adopt(s.now(), check) // the interface outlived the previous agent
	} else {
		v = t.monitor.Observe(s.now(), check)
	}
	t.checked = true
	if state.Up && state.HandshakeAge > 0 && state.HandshakeAge <= staleHandshake {
		t.handshook = s.now()
	}
	action := v.Action
	renewed := false
	if !v.Healthy && t.renewDue(s.now()) {
		// Nothing brought it back and it has had no handshake for long: its
		// credentials are what failed. New ones, then a new interface.
		t.renewed, renewed = s.now(), true
		if err := s.renew.Renew(ctx, e); err != nil {
			errs = append(errs, fmt.Errorf("renew: %w", err))
		} else {
			action = ActionRecreate
		}
	}
	present, recreated := state.Up, false
	if err := s.act(ctx, t, action); err != nil {
		errs = append(errs, err)
	} else if action == ActionRecreate {
		present, recreated = true, true
	}

	t.last = Status{
		Name: e.Name, Slot: e.Slot,
		Present: present, Healthy: v.Healthy, Changed: v.Changed, Alert: v.Alert,
		Recreated: recreated, Renewed: renewed,
	}
	return t.last, errors.Join(errs...)
}

func (s *Supervisor) act(ctx context.Context, t *tracked, action Action) error {
	switch action {
	case ActionResetPeer:
		return wrap("reset peer", s.dev.ResetPeer(ctx, t.exit, t.currentEndpoint()))
	case ActionNextEndpoint:
		t.endpoint = (t.endpoint + 1) % len(t.exit.Endpoints)
		return wrap("switch endpoint", s.dev.ResetPeer(ctx, t.exit, t.currentEndpoint()))
	case ActionRecreate:
		return wrap("recreate", s.dev.Recreate(ctx, t.exit, t.currentEndpoint()))
	default:
		return nil
	}
}

// track returns the tracking state of e, starting it — or restarting it when
// the exit's definition changed.
func (s *Supervisor) track(e policy.Exit) *tracked {
	t, ok := s.exits[e.Name]
	if !ok || !sameExit(t.exit, e) {
		t = &tracked{exit: e, last: Status{Name: e.Name, Slot: e.Slot}, handshook: s.now()}
		s.exits[e.Name] = t
	}
	return t
}

// Retire removes the interface of an exit that left the policy while no agent
// tracked it — renamed, or dropped across a restart; a missing interface is
// not an error.
func (s *Supervisor) Retire(ctx context.Context, iface string) error {
	return s.dev.Remove(ctx, iface)
}

// renewDue reports whether the exit's renew command is due: it has one, has
// had no handshake for its After, and did not run it within its Every.
func (t *tracked) renewDue(now time.Time) bool {
	r := t.exit.Renew
	return r != nil && now.Sub(t.handshook) >= r.After && (t.renewed.IsZero() || now.Sub(t.renewed) >= r.Every)
}

// unchanged is the last status again, reported as no change.
func (t *tracked) unchanged() Status {
	st := t.last
	st.Changed = false
	return st
}

func (t *tracked) adoptEndpoint(current netip.AddrPort) {
	if i := slices.Index(t.exit.Endpoints, current); i >= 0 {
		t.endpoint = i
	}
}

func (t *tracked) currentEndpoint() netip.AddrPort {
	return t.exit.Endpoints[t.endpoint%len(t.exit.Endpoints)]
}

func sameExit(a, b policy.Exit) bool {
	return a.Slot == b.Slot && a.Iface == b.Iface && a.Conf == b.Conf && slices.Equal(a.Endpoints, b.Endpoints)
}

func wrap(what string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", what, err)
}
