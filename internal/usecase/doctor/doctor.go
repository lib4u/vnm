// Package doctor checks a node end to end (ТЗ §8, `vnm doctor`): the policy
// file, the units, the agent's last pass, the kernel against the applied state,
// the exits, the resolver, the lists — and the one foreign setting the agent
// cannot fix but must warn about, a FORWARD policy of DROP (ТЗ §3.3).
package doctor

import (
	"bytes"
	"context"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/lib4u/vnm/internal/domain/netstate"
	"github.com/lib4u/vnm/internal/domain/policy"
	"github.com/lib4u/vnm/internal/usecase/agent"
	"github.com/lib4u/vnm/internal/usecase/install"
)

// Thresholds (ТЗ §7.4, §7.5).
const (
	// A list's copies older than these multiples of its refresh have missed
	// that many downloads in a row.
	listsWarn = 3
	listsFail = 7
)

// Level is how bad a finding is.
type Level uint8

const (
	LevelOK Level = iota + 1
	LevelWarn
	LevelFail
)

func (l Level) String() string {
	switch l {
	case LevelOK:
		return "ok"
	case LevelWarn:
		return "WARN"
	case LevelFail:
		return "FAIL"
	default:
		return "?"
	}
}

// Finding is the result of one check.
type Finding struct {
	Check  string
	Level  Level
	Detail string
}

// Config loads the policy file.
type Config interface {
	Load() (cfg policy.Config, version string, err error)
}

// Status reads the agent's last snapshot.
type Status interface {
	Read() (agent.Snapshot, error)
}

// Units reads systemd.
type Units interface {
	Active(ctx context.Context, unit string) bool
	Enabled(ctx context.Context, unit string) bool
}

// Kernel verifies that the kernel holds a state.
type Kernel interface {
	Verify(ctx context.Context, s netstate.State) error
}

// Store holds the applied state.
type Store interface {
	LastGood() (s netstate.State, ok bool, err error)
}

// Forward reads the policy of the iptables FORWARD chain.
type Forward interface {
	ForwardPolicy(ctx context.Context) (string, error)
}

// Firewall reads the host firewall.
type Firewall interface {
	// PortAllowed reports whether the active host firewall lets a port in
	// over UDP; firewall is "" when none is active.
	PortAllowed(ctx context.Context, port uint16) (firewall string, allowed bool, err error)
	// ForwardAllowedTo reports whether the active host firewall forwards to
	// an interface; firewall is "" when none restricts it.
	ForwardAllowedTo(ctx context.Context, iface string) (firewall string, allowed bool, err error)
}

// Deps are the doctor's collaborators.
type Deps struct {
	Config   Config
	Status   Status
	Units    Units
	Kernel   Kernel
	Store    Store
	Forward  Forward
	Firewall Firewall
	Files    Files
	Now      func() time.Time
}

// Files reads files.
type Files interface {
	Read(path string) ([]byte, error)
}

// The distribution's nftables service and its ruleset.
const (
	nftablesUnit = "nftables.service"
	nftablesConf = "/etc/nftables.conf"
)

// Doctor runs the checks.
type Doctor struct {
	d Deps
}

// New returns a Doctor.
func New(d Deps) *Doctor {
	return &Doctor{d: d}
}

// Run runs every check. A check that cannot run is itself a finding.
func (dr *Doctor) Run(ctx context.Context) []Finding {
	var out []Finding
	add := func(check string, level Level, format string, args ...any) {
		out = append(out, Finding{Check: check, Level: level, Detail: fmt.Sprintf(format, args...)})
	}

	cfg, _, err := dr.d.Config.Load()
	valid := err == nil
	if valid {
		add("config", LevelOK, "valid, mode %s, guard %s, p2p %s", cfg.Mode, cfg.Guard.Mode, cfg.P2P.Mode)
	} else {
		add("config", LevelFail, "%v — the last valid policy stays in force", err)
	}

	if valid && cfg.EgressActive() {
		dr.exitForwarding(ctx, cfg, add)
	}
	usesDomains := valid && cfg.EgressActive() && cfg.UsesDomains()
	dr.units(ctx, usesDomains, add)
	if usesDomains {
		dr.resolverPort(ctx, cfg.DNS.Port, add)
	}
	dr.kernel(ctx, add)
	dr.forward(ctx, add)
	dr.nftablesService(ctx, add)

	snap, err := dr.d.Status.Read()
	if err != nil {
		add("agent", LevelFail, "%v", err)
		return out
	}
	dr.agent(snap, add)
	// Without a readable policy every list the agent reports counts as used.
	var uses map[string]policy.ListUse
	if valid {
		uses = cfg.ListUses()
	}
	dr.lists(snap, uses, add)
	return out
}

type adder func(check string, level Level, format string, args ...any)

func (dr *Doctor) units(ctx context.Context, usesDomains bool, add adder) {
	if dr.d.Units.Enabled(ctx, install.BootUnit) {
		add("boot unit", LevelOK, "enabled: the policy is restored before the network at boot")
	} else {
		add("boot unit", LevelFail, "%s is not enabled: a reboot leaves a window without the policy", install.BootUnit)
	}
	if dr.d.Units.Active(ctx, install.AgentUnit) {
		add("agent unit", LevelOK, "active")
	} else {
		add("agent unit", LevelFail, "%s is not running: exits are not checked, a dead one is not refused", install.AgentUnit)
	}
	if !usesDomains {
		return
	}
	if dr.d.Units.Active(ctx, install.DNSUnit) {
		add("resolver unit", LevelOK, "active")
	} else {
		add("resolver unit", LevelFail, "%s is not running: domain lists are not filled", install.DNSUnit)
	}
}

func (dr *Doctor) kernel(ctx context.Context, add adder) {
	last, ok, err := dr.d.Store.LastGood()
	switch {
	case err != nil:
		add("kernel", LevelFail, "applied state: %v", err)
	case !ok:
		add("kernel", LevelWarn, "no state applied yet")
	default:
		if err := dr.d.Kernel.Verify(ctx, last); err != nil {
			add("kernel", LevelFail, "%v", err)
		} else {
			add("kernel", LevelOK, "holds the applied state")
		}
	}
}

func (dr *Doctor) forward(ctx context.Context, add adder) {
	pol, err := dr.d.Forward.ForwardPolicy(ctx)
	switch {
	case err != nil:
		add("forward", LevelWarn, "FORWARD policy unknown: %v", err)
	case pol == "DROP":
		add("forward", LevelWarn, "iptables FORWARD policy is DROP: transit reaches an exit only if the owner "+
			"of each downstream interface accepts its forwarding to any output interface (ТЗ §3.3)")
	default:
		add("forward", LevelOK, "iptables FORWARD policy %s", pol)
	}
}

// resolverPort checks that the host firewall lets redirected DNS reach the
// resolver: DNS from a tunnel is delivered locally, and a firewall dropping
// the port leaves the tunnel's clients without DNS at all.
func (dr *Doctor) resolverPort(ctx context.Context, port uint16, add adder) {
	fw, allowed, err := dr.d.Firewall.PortAllowed(ctx, port)
	switch {
	case err != nil:
		add("resolver port", LevelWarn, "%s: cannot tell whether port %d is allowed: %v", fw, port, err)
	case fw == "":
		add("resolver port", LevelOK, "no host firewall in the way")
	case allowed:
		add("resolver port", LevelOK, "%s allows %d", fw, port)
	default:
		add("resolver port", LevelFail, "%s drops port %d: DNS redirected from downstream interfaces never reaches "+
			"the resolver, and tunnel clients lose DNS — run `vnm install -skip-base` or allow the port", fw, port)
	}
}

// exitForwarding checks that the host firewall forwards to every exit: firewalld
// rejects forwarding to an interface outside its zones, and tunnel clients then
// find every destination sent through the exit unreachable.
func (dr *Doctor) exitForwarding(ctx context.Context, cfg policy.Config, add adder) {
	for _, e := range cfg.Exits {
		fw, allowed, err := dr.d.Firewall.ForwardAllowedTo(ctx, e.Iface)
		check := "exit " + e.Name + " forwarding"
		switch {
		case err != nil:
			add(check, LevelWarn, "%s: cannot tell whether forwarding to %s is allowed: %v", fw, e.Iface, err)
		case fw == "" || allowed:
			add(check, LevelOK, "the host firewall forwards to %s", e.Iface)
		default:
			add(check, LevelFail, "%s rejects forwarding to %s: tunnel clients find the exit's destinations "+
				"unreachable — run `vnm install -skip-base` or add %s to a zone", fw, e.Iface, e.Iface)
		}
	}
}

// nftablesService warns about the one foreign unit that removes the vnm table:
// the distribution's nftables service, whose ruleset starts with `flush
// ruleset`. At boot vnm-boot runs after it; a restart of it later wipes the
// policy until the agent's next pass.
func (dr *Doctor) nftablesService(ctx context.Context, add adder) {
	if !dr.d.Units.Enabled(ctx, nftablesUnit) {
		return
	}
	conf, err := dr.d.Files.Read(nftablesConf)
	if err != nil || !bytes.Contains(conf, []byte("flush ruleset")) {
		return
	}
	add("nftables", LevelWarn, "%s is enabled and %s flushes the whole ruleset: restarting it removes the vnm "+
		"table until the agent's next pass; replace `flush ruleset` with the flush of its own tables", nftablesUnit, nftablesConf)
}

func (dr *Doctor) agent(s agent.Snapshot, add adder) {
	if age := dr.d.Now().Sub(s.LastReconcile); age > agent.StaleAfter {
		add("agent", LevelFail, "last pass %v ago", age.Round(time.Second))
	} else {
		add("agent", LevelOK, "last pass %v ago, %d apply errors, %d drifts", age.Round(time.Second), s.ApplyErrors, s.Drift)
	}

	switch {
	case !s.ConfigValid:
		// Reported by the config check already.
	case !s.PolicyApplied:
		add("policy", LevelFail, "the policy in the file is not applied: it cannot be planned or applied, "+
			"see `journalctl -u vnm-agent`")
	case !s.ListsCurrent:
		add("policy", LevelWarn, "applied with older lists: the latest copies did not resolve")
	default:
		add("policy", LevelOK, "applied")
	}

	switch s.Mode {
	case policy.ModeEnforce:
		add("mode", LevelOK, "enforce")
	case policy.ModeObserve:
		add("mode", LevelWarn, "observe: decisions are counted, traffic is unchanged")
	default:
		add("mode", LevelWarn, "%s: no policy on the node", s.Mode)
	}

	for _, e := range s.Exits {
		check := "exit " + e.Name
		switch {
		case e.Healthy:
			add(check, LevelOK, "healthy")
		case !e.Present:
			add(check, LevelFail, "interface missing: its traffic is refused")
		default:
			add(check, LevelFail, "dead: its traffic is refused")
		}
	}

	if s.Resolver.Enabled {
		if s.Resolver.Up {
			add("resolver", LevelOK, "answers, DNS redirected to it")
		} else {
			add("resolver", LevelWarn, "not answering: DNS goes where it was sent, domain lists are not filled")
		}
	}

	switch s.Guard.Mode {
	case policy.ModeEnforce:
		add("guard", LevelOK, "enforce, %d connection attempts refused", sum(s.Guard.Refused))
	case policy.ModeObserve:
		add("guard", LevelWarn, "observe: %d connection attempts would be refused, none is", sum(s.Guard.Refused))
	default:
		add("guard", LevelOK, "%s", s.Guard.Mode)
	}

	switch s.P2P.Mode {
	case policy.ModeEnforce:
		add("p2p", LevelOK, "enforce, %d BitTorrent packets refused", sum(s.P2P.Refused))
	case policy.ModeObserve:
		add("p2p", LevelWarn, "observe: %d BitTorrent packets would be refused, none is", sum(s.P2P.Refused))
	default:
		add("p2p", LevelOK, "%s", s.P2P.Mode)
	}
	if s.P2P.NDPI {
		if s.P2P.Connected {
			add("p2p ndpi", LevelOK, "nDPId writing; %d BitTorrent flows found, %d peers refused, %d clients banned", s.P2P.Detections, s.P2P.Peers, s.P2P.Bans)
		} else {
			add("p2p ndpi", LevelFail, "nDPId is not writing to the agent: encrypted BitTorrent is not caught (is vnm-ndpid running?)")
		}
	}
}

// lists checks every list the policy applies; a list no active part uses
// cannot fail the node. uses nil means every list counts.
func (dr *Doctor) lists(s agent.Snapshot, uses map[string]policy.ListUse, add adder) {
	for _, name := range slices.Sorted(maps.Keys(s.Lists)) {
		st := s.Lists[name]
		if _, used := uses[name]; uses != nil && !used {
			continue
		}
		check := "list " + name
		switch {
		case st.Missing:
			add(check, LevelFail, "a remote source has no local copy")
		case st.Failed && st.Entries == 0:
			add(check, LevelFail, "did not resolve: it guards nothing")
		case st.Failed:
			add(check, LevelWarn, "the latest copy did not resolve; the previous %d ranges stay", st.Entries)
		case st.Refresh > 0 && st.Age > listsFail*st.Refresh:
			add(check, LevelFail, "copies %v old, refresh %v", st.Age.Round(time.Hour), st.Refresh)
		case st.Refresh > 0 && st.Age > listsWarn*st.Refresh:
			add(check, LevelWarn, "copies %v old, refresh %v", st.Age.Round(time.Hour), st.Refresh)
		case st.Refresh > 0:
			add(check, LevelOK, "%d ranges, copies %v old", st.Entries, st.Age.Round(time.Minute))
		default:
			add(check, LevelOK, "%d ranges", st.Entries)
		}
	}
}

func sum(counts map[string]uint64) uint64 {
	var n uint64
	for _, c := range counts {
		n += c
	}
	return n
}

// Failed reports whether any finding is a failure.
func Failed(findings []Finding) bool {
	for _, f := range findings {
		if f.Level == LevelFail {
			return true
		}
	}
	return false
}
