package policy

// Guard is the inbound part of the policy (guard ТЗ): a new connection that
// arrives from an uplink with a source in one of the guard's lists never
// reaches the node. It is independent of the egress mode — `mode: off` lifts
// the destination policy, not the guard.
type Guard struct {
	// Mode is ModeOff unless the file sets it: a guard is never switched on
	// by default.
	Mode  Mode
	Rules []GuardRule
}

// GuardAction is what a guarded source's new connection gets.
type GuardAction uint8

const (
	GuardUnknown GuardAction = iota
	// GuardDrop discards the packet: the port looks absent.
	GuardDrop
	// GuardReject answers with a reset or an ICMP error.
	GuardReject
)

// GuardRule applies an action to the sources in its lists.
type GuardRule struct {
	Lists  []string
	Action GuardAction
	// Log writes matches to the kernel log, rate-limited.
	Log bool
}

// Active reports whether the guard is applied, counting only or not.
func (g Guard) Active() bool {
	return (g.Mode == ModeObserve || g.Mode == ModeEnforce) && len(g.Rules) > 0
}

// EgressActive reports whether the destination policy is applied, counting
// only or not.
func (c Config) EgressActive() bool {
	return c.Mode == ModeObserve || c.Mode == ModeEnforce
}

// ListUse is how the active parts of the policy use a list.
type ListUse struct {
	// Egress lists are strict: without them the destination policy cannot be
	// planned, since an unresolved list would let its destinations out
	// directly (I-1).
	Egress bool
	// Guard lists fail open one by one: a list that did not resolve guards
	// nothing, and nothing else waits for it (G-4).
	Guard bool
}

// ListUses returns how the active parts of the policy use each list; a list
// no active part applies is absent.
func (c Config) ListUses() map[string]ListUse {
	uses := map[string]ListUse{}
	if c.EgressActive() {
		for _, r := range c.Rules {
			for _, name := range r.Lists {
				u := uses[name]
				u.Egress = true
				uses[name] = u
			}
		}
	}
	if c.Guard.Active() {
		for _, r := range c.Guard.Rules {
			for _, name := range r.Lists {
				u := uses[name]
				u.Guard = true
				uses[name] = u
			}
		}
	}
	return uses
}

func (c Config) validateGuard(p *problems) {
	if len(c.Guard.Rules) > 0 && c.Guard.Mode == ModeUnknown {
		p.add("guard: mode is not set")
	}
	lists := make([][]string, 0, len(c.Guard.Rules))
	for _, r := range c.Guard.Rules {
		lists = append(lists, r.Lists)
	}
	for _, name := range repeated(lists) {
		p.add("guard: list %q is named more than once", name)
	}
	for i, r := range c.Guard.Rules {
		if len(r.Lists) == 0 {
			p.add("guard rule %d names no lists", i)
		}
		for _, name := range r.Lists {
			list, ok := c.List(name)
			switch {
			case !ok:
				p.add("guard rule %d: list %q is not defined", i, name)
			case list.HasDomainEntries():
				// A domain has no source address: an inbound packet carries
				// none of its names.
				p.add("guard rule %d: list %q has domain entries, a guard matches source addresses only", i, name)
			}
		}
		if r.Action == GuardUnknown {
			p.add("guard rule %d: action is not set", i)
		}
	}
}
