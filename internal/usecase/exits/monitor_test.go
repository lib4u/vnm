package exits_test

import (
	"slices"
	"testing"
	"time"

	"github.com/lib4u/vnm/internal/usecase/exits"
)

var (
	pass       = exits.Check{LinkUp: true, HandshakeAge: 30 * time.Second, ProbeOK: true}
	probeFails = exits.Check{LinkUp: true, HandshakeAge: 30 * time.Second}
	staleShake = exits.Check{LinkUp: true, HandshakeAge: 181 * time.Second, ProbeOK: true}
	linkGone   = exits.Check{}
)

// clock steps by the check interval of ТЗ §4.
type clock struct{ now time.Time }

func (c *clock) tick() time.Time {
	c.now = c.now.Add(15 * time.Second)
	return c.now
}

func feed(m *exits.Monitor, c *clock, checks ...exits.Check) []exits.Verdict {
	out := make([]exits.Verdict, 0, len(checks))
	for _, ch := range checks {
		out = append(out, m.Observe(c.tick(), ch))
	}
	return out
}

func repeat(c exits.Check, n int) []exits.Check {
	out := make([]exits.Check, n)
	for i := range out {
		out[i] = c
	}
	return out
}

// becomeHealthy brings a fresh monitor to a live exit.
func becomeHealthy(t *testing.T) (*exits.Monitor, *clock) {
	t.Helper()
	m, c := &exits.Monitor{}, &clock{now: time.Unix(0, 0)}
	vs := feed(m, c, repeat(pass, 4)...)
	if !vs[3].Healthy || !vs[3].Changed {
		t.Fatalf("after 4 passed checks: %+v", vs[3])
	}
	return m, c
}

func TestStartsDeadAndNeedsFourPasses(t *testing.T) {
	m, c := &exits.Monitor{}, &clock{now: time.Unix(0, 0)}
	vs := feed(m, c, repeat(pass, 3)...)
	for i, v := range vs {
		if v.Healthy {
			t.Fatalf("check %d: healthy before proving itself four times", i)
		}
	}
	if v := m.Observe(c.tick(), pass); !v.Healthy || !v.Changed {
		t.Fatalf("fourth pass: %+v", v)
	}
}

func TestThreeFailuresDeclareDead(t *testing.T) {
	m, c := becomeHealthy(t)
	vs := feed(m, c, probeFails, probeFails)
	for _, v := range vs {
		if !v.Healthy || v.Action != exits.ActionNone {
			t.Fatalf("dead too early: %+v", v)
		}
	}
	v := m.Observe(c.tick(), probeFails)
	if v.Healthy || !v.Changed || v.Action != exits.ActionResetPeer {
		t.Fatalf("third failure: %+v, want dead + reset peer", v)
	}
}

// A fresh handshake does not make a tunnel alive if nothing gets through, and a
// working probe does not hide a handshake that stopped.
func TestEveryCheckMustPass(t *testing.T) {
	for name, ch := range map[string]exits.Check{"probe fails": probeFails, "stale handshake": staleShake} {
		t.Run(name, func(t *testing.T) {
			if ch.Passed() {
				t.Fatal("check passed")
			}
		})
	}
}

func TestLinkGoneIsDeadAtOnce(t *testing.T) {
	m, c := becomeHealthy(t)
	v := m.Observe(c.tick(), linkGone)
	if v.Healthy || !v.Changed || v.Action != exits.ActionRecreate {
		t.Fatalf("link gone: %+v, want dead + recreate at once", v)
	}
}

// The ladder repeats while the exit stays dead: a single pass would leave the
// exit on its second endpoint forever and never try a third.
func TestRecoveryLadderRepeats(t *testing.T) {
	m, c := becomeHealthy(t)
	var actions []exits.Action
	for _, v := range feed(m, c, repeat(probeFails, 15)...) {
		if v.Action != exits.ActionNone {
			actions = append(actions, v.Action)
		}
	}
	want := []exits.Action{
		exits.ActionResetPeer, exits.ActionNextEndpoint, exits.ActionRecreate,
		exits.ActionResetPeer, exits.ActionNextEndpoint,
	}
	if !slices.Equal(actions, want) {
		t.Fatalf("ladder = %v, want %v", actions, want)
	}
}

func TestAlertAfterFifteenMinutesDead(t *testing.T) {
	m, c := becomeHealthy(t)
	var firstAlert time.Time
	deadAt := time.Time{}
	for range 100 {
		v := m.Observe(c.tick(), probeFails)
		if !v.Healthy && deadAt.IsZero() {
			deadAt = c.now
		}
		if v.Alert {
			firstAlert = c.now
			break
		}
	}
	if got := firstAlert.Sub(deadAt); got != 15*time.Minute {
		t.Fatalf("alert after %v dead, want 15m", got)
	}
}

func TestRecoveryResetsLadder(t *testing.T) {
	m, c := becomeHealthy(t)
	feed(m, c, repeat(probeFails, 6)...)
	feed(m, c, repeat(pass, 4)...)
	v := feed(m, c, repeat(probeFails, 3)...)[2]
	if v.Action != exits.ActionResetPeer {
		t.Fatalf("after recovery the ladder must start over, got %+v", v)
	}
}

// A working exit found at start is trusted on one full check; a failing one
// is treated like any other.
func TestAdopt(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	m := &exits.Monitor{}
	if v := m.Adopt(c.tick(), pass); !v.Healthy || !v.Changed {
		t.Fatalf("adopting a working exit: %+v", v)
	}
	m = &exits.Monitor{}
	if v := m.Adopt(c.tick(), probeFails); v.Healthy {
		t.Fatalf("adopting a failing exit: %+v", v)
	}
}

// One passing check in the middle of an outage does not bring the exit back.
func TestNoFlapOnSinglePass(t *testing.T) {
	m, c := becomeHealthy(t)
	feed(m, c, repeat(probeFails, 3)...)
	vs := feed(m, c, pass, probeFails, pass, pass, pass)
	for i, v := range vs {
		if v.Healthy {
			t.Fatalf("check %d: back to healthy without four passes in a row", i)
		}
	}
}
