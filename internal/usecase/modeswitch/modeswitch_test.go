package modeswitch_test

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/lib4u/vnm/internal/domain/policy"
	"github.com/lib4u/vnm/internal/infrastructure/configfile"
	"github.com/lib4u/vnm/internal/usecase/modeswitch"
)

const (
	configPath   = "/etc/vnm/config.yaml"
	previousPath = "/run/vnm/egress-previous.yaml"
)

type host struct {
	files     map[string][]byte
	scheduled []string
	cancelled int
	locks     int
}

func (h *host) Read(path string) ([]byte, error) {
	data, ok := h.files[path]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return data, nil
}

func (h *host) Write(path string, data []byte, _ os.FileMode) (bool, error) {
	h.files[path] = data
	return true, nil
}

func (h *host) Exists(path string) bool { _, ok := h.files[path]; return ok }

func (h *host) Remove(path string) error { delete(h.files, path); return nil }

func (h *host) Schedule(_ context.Context, name string, _ time.Duration, command ...string) error {
	h.scheduled = append(append(h.scheduled, name), command...)
	return nil
}

func (h *host) Cancel(context.Context, string) error { h.cancelled++; return nil }

func (h *host) Lock(context.Context) (func() error, error) {
	h.locks++
	return func() error { h.locks--; return nil }, nil
}

func setup(t *testing.T, mode policy.Mode) (*host, *modeswitch.Switcher) {
	t.Helper()
	data, err := os.ReadFile("../../../configs/vnm.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if data, err = configfile.WithMode(data, []string{"mode"}, mode); err != nil {
		t.Fatal(err)
	}
	h := &host{files: map[string][]byte{configPath: data}}
	return h, modeswitch.New(modeswitch.Deps{
		Files: h, Policy: configfile.Format{}, Scheduler: h, Lock: h,
		Paths: modeswitch.Paths{Config: configPath, ConfigMode: 0o644, Previous: previousPath, Binary: "/usr/local/bin/vnm"},
	})
}

func mode(t *testing.T, h *host) policy.Mode {
	t.Helper()
	cfg, err := configfile.Parse(h.files[configPath])
	if err != nil {
		t.Fatal(err)
	}
	return cfg.Mode
}

func TestLeavingEnforceNeedsConsent(t *testing.T) {
	for _, to := range []policy.Mode{policy.ModeObserve, policy.ModeOff} {
		h, s := setup(t, policy.ModeEnforce)
		if _, err := s.Set(context.Background(), modeswitch.Egress, to, modeswitch.Options{}); !errors.Is(err, modeswitch.ErrLeak) {
			t.Fatalf("enforce → %s without consent: %v", to, err)
		}
		if mode(t, h) != policy.ModeEnforce {
			t.Fatal("the policy changed anyway")
		}
		if res, err := s.Set(context.Background(), modeswitch.Egress, to, modeswitch.Options{AllowLeak: true}); err != nil || !res.Changed || mode(t, h) != to {
			t.Fatalf("with consent: %+v %v", res, err)
		}
		if h.locks != 0 {
			t.Fatal("the lock was not released")
		}
	}
}

func TestSameModeChangesNothing(t *testing.T) {
	h, s := setup(t, policy.ModeEnforce)
	before := string(h.files[configPath])
	if res, err := s.Set(context.Background(), modeswitch.Egress, policy.ModeEnforce, modeswitch.Options{}); err != nil || res.Changed {
		t.Fatalf("%+v %v", res, err)
	}
	if string(h.files[configPath]) != before {
		t.Fatal("file rewritten")
	}
}

func TestProvisionalSwitchRollsBack(t *testing.T) {
	h, s := setup(t, policy.ModeObserve)
	ctx := context.Background()
	if _, err := s.Set(ctx, modeswitch.Egress, policy.ModeEnforce, modeswitch.Options{AutoRollback: 5 * time.Minute}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(h.scheduled, []string{modeswitch.RollbackUnit, "/usr/local/bin/vnm", "egress", "rollback"}) {
		t.Fatalf("scheduled %v", h.scheduled)
	}
	if mode(t, h) != policy.ModeEnforce {
		t.Fatal("not switched")
	}
	// A second switch waits for the first to be settled.
	if _, err := s.Set(ctx, modeswitch.Egress, policy.ModeOff, modeswitch.Options{AllowLeak: true}); !errors.Is(err, modeswitch.ErrPending) {
		t.Fatalf("second switch: %v", err)
	}
	back, err := s.Rollback(ctx)
	if err != nil || back.Mode != policy.ModeObserve || mode(t, h) != policy.ModeObserve || h.Exists(previousPath) {
		t.Fatalf("rollback: %s %v", back.Mode, err)
	}
	if _, err := s.Rollback(ctx); !errors.Is(err, modeswitch.ErrNothingPending) {
		t.Fatalf("second rollback: %v", err)
	}
}

func TestConfirmKeepsTheSwitch(t *testing.T) {
	h, s := setup(t, policy.ModeObserve)
	ctx := context.Background()
	if _, err := s.Set(ctx, modeswitch.Egress, policy.ModeEnforce, modeswitch.Options{AutoRollback: time.Minute}); err != nil {
		t.Fatal(err)
	}
	if err := s.Confirm(ctx); err != nil || h.cancelled != 1 || h.Exists(previousPath) {
		t.Fatalf("confirm: %v cancelled %d", err, h.cancelled)
	}
	if mode(t, h) != policy.ModeEnforce {
		t.Fatal("confirm changed the mode")
	}
	if err := s.Confirm(ctx); !errors.Is(err, modeswitch.ErrNothingPending) {
		t.Fatalf("second confirm: %v", err)
	}
}

// The guard has its own mode: lowering it needs no consent, and while one
// provisional switch is pending no other part switches.
func TestGuardSwitch(t *testing.T) {
	h, s := setup(t, policy.ModeEnforce)
	ctx := context.Background()
	guard := func() policy.Mode {
		cfg, err := configfile.Parse(h.files[configPath])
		if err != nil {
			t.Fatal(err)
		}
		return cfg.Guard.Mode
	}
	res, err := s.Set(ctx, modeswitch.Guard, policy.ModeEnforce, modeswitch.Options{AutoRollback: 5 * time.Minute})
	if err != nil || res.From != policy.ModeOff || guard() != policy.ModeEnforce || mode(t, h) != policy.ModeEnforce {
		t.Fatalf("%+v %v", res, err)
	}
	if !slices.Equal(h.scheduled[1:], []string{"/usr/local/bin/vnm", "guard", "rollback"}) {
		t.Fatalf("scheduled %v", h.scheduled)
	}
	if _, err := s.Set(ctx, modeswitch.Egress, policy.ModeObserve, modeswitch.Options{AllowLeak: true}); !errors.Is(err, modeswitch.ErrPending) {
		t.Fatalf("egress switch during a pending guard switch: %v", err)
	}
	if err := s.Confirm(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Set(ctx, modeswitch.Guard, policy.ModeOff, modeswitch.Options{}); err != nil || guard() != policy.ModeOff {
		t.Fatalf("guard off: %v", err)
	}
}

// Off opens the node from any mode.
func TestOffAlwaysNeedsConsent(t *testing.T) {
	_, s := setup(t, policy.ModeObserve)
	if _, err := s.Set(context.Background(), modeswitch.Egress, policy.ModeOff, modeswitch.Options{}); !errors.Is(err, modeswitch.ErrLeak) {
		t.Fatalf("observe → off without consent: %v", err)
	}
}

// The rollback runs with the paths of the switch, not the defaults.
func TestRollbackCarriesThePaths(t *testing.T) {
	h, _ := setup(t, policy.ModeObserve)
	s := modeswitch.New(modeswitch.Deps{
		Files: h, Policy: configfile.Format{}, Scheduler: h, Lock: h,
		Paths: modeswitch.Paths{
			Config: configPath, ConfigMode: 0o644, Previous: previousPath,
			Binary: "/usr/local/bin/vnm", Args: []string{"-config", configPath},
		},
	})
	if _, err := s.Set(context.Background(), modeswitch.Egress, policy.ModeEnforce, modeswitch.Options{AutoRollback: time.Minute}); err != nil {
		t.Fatal(err)
	}
	want := []string{modeswitch.RollbackUnit, "/usr/local/bin/vnm", "egress", "rollback", "-config", configPath}
	if !slices.Equal(h.scheduled, want) {
		t.Fatalf("scheduled %v, want %v", h.scheduled, want)
	}
}
