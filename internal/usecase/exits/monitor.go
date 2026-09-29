// Package exits decides whether an exit is alive and what to do when it is not
// (ТЗ §4).
//
// The Monitor is pure: it is fed the time and the result of each check, and
// answers with the exit's health and the recovery action due. The agent is the
// only controller of an exit's interface — no watchdog, cron or wg-quick unit
// runs beside it — so every decision about the interface is made here.
package exits

import "time"

// Thresholds of ТЗ §4.
const (
	// failuresToDead is how many failed checks in a row declare a live exit dead.
	failuresToDead = 3
	// successesToAlive is how many passed checks in a row bring a dead exit
	// back. It is higher than failuresToDead so the verdict does not flap.
	successesToAlive = 4
	// failuresPerStep is how many failed checks each recovery step gets before
	// the next one is tried.
	failuresPerStep = 3
	// alertAfter is how long an exit may stay dead before an alert is due.
	alertAfter = 15 * time.Minute
	// MaxHandshakeAge is the oldest WireGuard handshake of a live exit.
	MaxHandshakeAge = 180 * time.Second
)

// Check is the result of one health check.
type Check struct {
	// LinkUp means the interface exists and is up.
	LinkUp bool
	// HandshakeAge is the age of the last WireGuard handshake; zero means no
	// handshake yet.
	HandshakeAge time.Duration
	// ProbeOK means the probe URL answered through the exit with the expected
	// body.
	ProbeOK bool
}

// Passed reports whether every sign of life is present. A fresh handshake with
// a failing probe is a failure: a tunnel without internet is a dead tunnel.
func (c Check) Passed() bool {
	fresh := c.HandshakeAge > 0 && c.HandshakeAge <= MaxHandshakeAge
	return c.LinkUp && fresh && c.ProbeOK
}

// Action is a recovery step.
type Action uint8

const (
	ActionNone Action = iota
	// ActionResetPeer re-applies the peer, forcing a new handshake.
	ActionResetPeer
	// ActionNextEndpoint switches to the next endpoint: some hosters drop the
	// default port, and Cloudflare accepts the same key on others.
	ActionNextEndpoint
	// ActionRecreate deletes and recreates the interface from its config.
	ActionRecreate
)

// ladder is the order of recovery steps; it repeats for as long as the exit
// stays dead, so every endpoint keeps being tried. Re-registration is never on
// it: that changes the exit's identity and is an installer operation.
var ladder = []Action{ActionResetPeer, ActionNextEndpoint, ActionRecreate}

// Verdict is the Monitor's answer to one check.
type Verdict struct {
	Healthy bool
	// Changed means Healthy differs from the previous verdict.
	Changed bool
	Action  Action
	// Alert means the exit has been dead longer than it may stay unnoticed.
	Alert bool
}

// Monitor tracks one exit. The zero value starts dead: an exit is trusted only
// after it has proven itself, never assumed alive at start.
type Monitor struct {
	healthy   bool
	failures  int
	successes int
	deadSince time.Time
	// step counts the recovery actions taken during this outage; the next one
	// is ladder[step % len(ladder)]. stepFailures counts failed checks since
	// the last action.
	step         int
	stepFailures int
}

// Observe feeds one check taken at now.
func (m *Monitor) Observe(now time.Time, c Check) Verdict {
	was := m.healthy
	if m.deadSince.IsZero() && !m.healthy {
		m.deadSince = now
	}

	if c.Passed() {
		m.successes++
		m.failures = 0
		if !m.healthy && m.successes >= successesToAlive {
			m.healthy = true
			m.deadSince = time.Time{}
			m.step, m.stepFailures = 0, 0
		}
		return Verdict{Healthy: m.healthy, Changed: m.healthy != was}
	}

	m.failures++
	m.successes = 0
	if m.healthy && (!c.LinkUp || m.failures >= failuresToDead) {
		m.healthy = false
		m.deadSince = now
	}
	if m.healthy {
		return Verdict{Healthy: true}
	}

	return Verdict{
		Healthy: false,
		Changed: was,
		Action:  m.nextAction(c),
		Alert:   now.Sub(m.deadSince) >= alertAfter,
	}
}

// Adopt feeds the first check of an exit whose interface was already running
// when the agent started — an agent restart over a working tunnel. If the check
// passes in full, the exit is trusted at once. The four-pass rule guards
// against a dead exit flapping back; applying it here would refuse the exit's
// traffic for a minute on every agent restart, for nothing. An exit the agent
// creates itself — after a reboot — still has to prove itself.
func (m *Monitor) Adopt(now time.Time, c Check) Verdict {
	if !c.Passed() {
		return m.Observe(now, c)
	}
	was := m.healthy
	m.healthy, m.successes, m.failures = true, successesToAlive, 0
	m.deadSince = time.Time{}
	return Verdict{Healthy: true, Changed: !was}
}

// nextAction climbs the ladder: one step when the exit is first found dead,
// the next after failuresPerStep more failed checks, starting over after the
// last. A missing interface skips straight to recreating it — nothing else can
// help.
func (m *Monitor) nextAction(c Check) Action {
	if !c.LinkUp {
		m.stepFailures = 0
		return ActionRecreate
	}
	m.stepFailures++
	if m.step > 0 && m.stepFailures < failuresPerStep {
		return ActionNone
	}
	action := ladder[m.step%len(ladder)]
	m.step++
	m.stepFailures = 0
	return action
}
