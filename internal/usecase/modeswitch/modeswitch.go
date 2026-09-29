// Package modeswitch switches the mode of a part of the policy — the egress
// (ТЗ §8) or the guard (guard ТЗ §5): observe, enforce or off.
//
// A switch edits the policy file; the agent applies it on its next pass. A
// switch that opens the node's own address to the listed destinations again
// takes explicit consent. A switch can be made provisional: it then rolls
// itself back after a while unless confirmed from a new session, like the SSH
// hardening. One provisional switch at a time: a rollback restores the whole
// file, and would undo a second one with it.
package modeswitch

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"

	"github.com/lib4u/vnm/internal/domain/policy"
)

// RollbackUnit is the transient unit that rolls a provisional switch back.
const RollbackUnit = "vnm-mode-rollback"

var (
	// ErrLeak means the switch lifts the destination policy without consent.
	ErrLeak = errors.New("this switch lets listed destinations out through the node's own address; pass -allow-leak")
	// ErrPending means a provisional switch awaits confirm or rollback.
	ErrPending = errors.New("a provisional switch is pending; confirm it or roll it back first")
	// ErrNothingPending means there is no provisional switch.
	ErrNothingPending = errors.New("no provisional switch is pending")
)

// Part is a part of the policy with a mode of its own.
type Part struct {
	// Name is the part's command: its rollback runs `vnm <name> rollback`.
	Name string
	// Key is the path of its mode in the policy file.
	Key []string
	// Mode reads its mode from a policy.
	Mode func(policy.Config) policy.Mode
	// Protects means a lower mode opens the node: leaving enforce, and off
	// from anywhere, take consent.
	Protects bool
}

var (
	// Egress is the destination policy: leaving enforce is a leak (I-1).
	Egress = Part{
		Name:     "egress",
		Key:      []string{"mode"},
		Mode:     func(c policy.Config) policy.Mode { return c.Mode },
		Protects: true,
	}
	// Guard is the inbound guard. Lowering it lets scanners in again but
	// opens nothing the node relies on; raising it is the risky direction,
	// which a provisional switch covers.
	Guard = Part{
		Name: "guard",
		Key:  []string{"guard", "mode"},
		Mode: func(c policy.Config) policy.Mode { return c.Guard.Mode },
	}
)

// Files reads and writes files.
type Files interface {
	// Read fails with fs.ErrNotExist for a missing file.
	Read(path string) ([]byte, error)
	Write(path string, data []byte, mode os.FileMode) (changed bool, err error)
	Exists(path string) bool
	Remove(path string) error
}

// Policy parses and edits the policy file.
type Policy interface {
	Parse(data []byte) (policy.Config, error)
	// WithMode returns the file with the mode at key replaced.
	WithMode(data []byte, key []string, mode policy.Mode) ([]byte, error)
}

// Scheduler runs a command once after a delay.
type Scheduler interface {
	Schedule(ctx context.Context, name string, after time.Duration, command ...string) error
	Cancel(ctx context.Context, name string) error
}

// Locker serialises state changes with the agent.
type Locker interface {
	Lock(ctx context.Context) (release func() error, err error)
}

// Paths are the files a switch touches.
type Paths struct {
	// Config is the policy file, written with ConfigMode.
	Config     string
	ConfigMode os.FileMode
	// Previous keeps the policy a provisional switch replaced. It belongs on
	// a tmpfs: it must not outlive the rollback timer, which a reboot drops.
	Previous string
	// Binary is the vnm executable the rollback runs, and Args the flags that
	// give it the paths of the switch.
	Binary string
	Args   []string
}

// Deps are the switcher's collaborators.
type Deps struct {
	Files     Files
	Policy    Policy
	Scheduler Scheduler
	Lock      Locker
	Paths     Paths
}

// Switcher switches the mode.
type Switcher struct {
	d Deps
}

// New returns a Switcher.
func New(d Deps) *Switcher {
	return &Switcher{d: d}
}

// Options qualify a switch.
type Options struct {
	// AllowLeak consents to opening the node's address.
	AllowLeak bool
	// AutoRollback, when set, makes the switch provisional: it is undone
	// after this long unless confirmed.
	AutoRollback time.Duration
}

// Result is what a switch did.
type Result struct {
	From, To policy.Mode
	// Changed is false when the policy already had the mode.
	Changed bool
}

// Set switches a part of the policy to mode.
func (s *Switcher) Set(ctx context.Context, part Part, mode policy.Mode, opt Options) (res Result, err error) {
	err = s.locked(ctx, func() error {
		res, err = s.set(ctx, part, mode, opt)
		return err
	})
	return res, err
}

func (s *Switcher) set(ctx context.Context, part Part, mode policy.Mode, opt Options) (Result, error) {
	if s.d.Files.Exists(s.d.Paths.Previous) {
		return Result{}, ErrPending
	}
	data, err := s.d.Files.Read(s.d.Paths.Config)
	if err != nil {
		return Result{}, fmt.Errorf("read policy: %w", err)
	}
	cfg, err := s.d.Policy.Parse(data)
	if err != nil {
		return Result{}, fmt.Errorf("the policy on disk is invalid, fix it first: %w", err)
	}
	res := Result{From: part.Mode(cfg), To: mode}
	if res.From == mode {
		return res, nil
	}
	opens := res.From == policy.ModeEnforce || mode == policy.ModeOff
	if part.Protects && opens && !opt.AllowLeak {
		return res, ErrLeak
	}
	edited, err := s.d.Policy.WithMode(data, part.Key, mode)
	if err != nil {
		return res, err
	}

	if opt.AutoRollback > 0 {
		if _, err := s.d.Files.Write(s.d.Paths.Previous, data, 0o600); err != nil {
			return res, fmt.Errorf("keep the previous policy: %w", err)
		}
		// Scheduled before the switch: a switch that could not be undone is
		// never made.
		command := append([]string{s.d.Paths.Binary, part.Name, "rollback"}, s.d.Paths.Args...)
		if err := s.d.Scheduler.Schedule(ctx, RollbackUnit, opt.AutoRollback, command...); err != nil {
			return res, errors.Join(fmt.Errorf("schedule rollback: %w", err), s.d.Files.Remove(s.d.Paths.Previous))
		}
	}
	if _, err := s.d.Files.Write(s.d.Paths.Config, edited, s.d.Paths.ConfigMode); err != nil {
		return res, fmt.Errorf("write policy: %w", err)
	}
	res.Changed = true
	return res, nil
}

// Confirm keeps a provisional switch.
func (s *Switcher) Confirm(ctx context.Context) error {
	return s.locked(ctx, func() error {
		if !s.d.Files.Exists(s.d.Paths.Previous) {
			return ErrNothingPending
		}
		if err := s.d.Scheduler.Cancel(ctx, RollbackUnit); err != nil {
			return fmt.Errorf("cancel rollback: %w", err)
		}
		return s.d.Files.Remove(s.d.Paths.Previous)
	})
}

// Rollback restores the policy a provisional switch replaced and returns it.
func (s *Switcher) Rollback(ctx context.Context) (cfg policy.Config, err error) {
	err = s.locked(ctx, func() error {
		cfg, err = s.rollback(ctx)
		return err
	})
	return cfg, err
}

func (s *Switcher) rollback(ctx context.Context) (policy.Config, error) {
	previous, err := s.d.Files.Read(s.d.Paths.Previous)
	if errors.Is(err, fs.ErrNotExist) {
		return policy.Config{}, ErrNothingPending
	}
	if err != nil {
		return policy.Config{}, fmt.Errorf("read the previous policy: %w", err)
	}
	cfg, err := s.d.Policy.Parse(previous)
	if err != nil {
		return policy.Config{}, fmt.Errorf("the previous policy is invalid: %w", err)
	}
	if _, err := s.d.Files.Write(s.d.Paths.Config, previous, s.d.Paths.ConfigMode); err != nil {
		return policy.Config{}, fmt.Errorf("restore policy: %w", err)
	}
	// The timer may be what runs this; cancelling it then is a no-op.
	return cfg, errors.Join(s.d.Scheduler.Cancel(ctx, RollbackUnit), s.d.Files.Remove(s.d.Paths.Previous))
}

// locked runs fn under the state lock.
func (s *Switcher) locked(ctx context.Context, fn func() error) (err error) {
	release, err := s.d.Lock.Lock(ctx)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, release()) }()
	return fn()
}
