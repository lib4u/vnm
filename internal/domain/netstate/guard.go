package netstate

// Guard is the inbound part of the state (guard ТЗ §4): a new connection that
// arrives from an uplink with a source in one of its sets is refused before it
// reaches any process or DNAT target. Exempt sources and connections the node
// itself opened are never refused.
type Guard struct {
	// Observe counts what enforce would refuse and refuses nothing.
	Observe bool
	// Rules are evaluated in order; the first match wins.
	Rules []GuardRule
}

// GuardRule refuses the sources in one set.
type GuardRule struct {
	// List is the policy list the set derives from.
	List   string
	Set    string
	Family Family
	// Reject answers the source; otherwise its packets are dropped.
	Reject bool
	// Log writes matches to the kernel log, rate-limited.
	Log bool
	// Counter names the counter that records the refused connections.
	Counter string
}

// Active reports whether the guard has anything to apply.
func (g Guard) Active() bool { return len(g.Rules) > 0 }

// Classifies reports whether connections are classified by destination: the
// egress policy is on. A state that only guards classifies nothing, and its
// table must leave every connection's mark alone.
func (c Classify) Classifies() bool { return len(c.Decisions) > 0 }
