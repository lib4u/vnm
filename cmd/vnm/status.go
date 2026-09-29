package main

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/lib4u/vnm/internal/app"
	"github.com/lib4u/vnm/internal/domain/netstate"
	"github.com/lib4u/vnm/internal/domain/policy"
	"github.com/lib4u/vnm/internal/usecase/agent"
	"github.com/lib4u/vnm/internal/usecase/inspect"
)

// runStatus prints what the agent saw on its last pass.
func runStatus(paths app.Paths) error {
	s, err := paths.Status().Read()
	if err != nil {
		return fmt.Errorf("%w (is vnm-agent running?)", err)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer w.Flush()

	age := time.Since(s.LastReconcile).Round(time.Second)
	agentLine := fmt.Sprintf("last pass %v ago", age)
	if age > agent.StaleAfter {
		agentLine += " — STALE, see `journalctl -u vnm-agent`"
	}
	if !s.ConfigValid {
		agentLine += "; config INVALID, the last valid one is in force"
	}
	fmt.Fprintf(w, "mode\t%s\n", s.Mode)
	fmt.Fprintf(w, "policy\t%s\n", policyLine(s))
	fmt.Fprintf(w, "guard\t%s\n", guardLine(s.Guard))
	fmt.Fprintf(w, "agent\t%s\n", agentLine)
	for _, e := range s.Exits {
		fmt.Fprintf(w, "exit %s\t%s\n", e.Name, exitLine(e.Present, e.Healthy, e.Alert))
	}
	if s.Resolver.Enabled {
		resolver := "up, DNS redirected to it"
		if !s.Resolver.Up {
			resolver = "DOWN, DNS not redirected: domain lists are not filled"
		}
		fmt.Fprintf(w, "resolver\t%s\n", resolver)
	}
	for _, name := range slices.Sorted(maps.Keys(s.Lists)) {
		fmt.Fprintf(w, "list %s\t%s\n", name, listLine(s.Lists[name]))
	}
	fmt.Fprintf(w, "counters\t%s\n", countersLine(s.Counters))
	fmt.Fprintf(w, "errors\tapply %d, drift %d (since the agent started)\n", s.ApplyErrors, s.Drift)
	return nil
}

func policyLine(s agent.Snapshot) string {
	switch {
	case !s.PolicyApplied:
		return "NOT APPLIED — it cannot be planned or applied, see `journalctl -u vnm-agent`"
	case !s.ListsCurrent:
		return "applied with older lists: the latest copies did not resolve"
	default:
		return "applied"
	}
}

func exitLine(present, healthy, alert bool) string {
	switch {
	case healthy:
		return "healthy"
	case !present:
		return "DEAD, interface missing"
	case alert:
		return "DEAD for over 15 min"
	default:
		return "DEAD"
	}
}

func guardLine(g agent.GuardSnapshot) string {
	if len(g.Refused) == 0 {
		return g.Mode.String()
	}
	verb := "refused"
	if g.Mode == policy.ModeObserve {
		verb = "would refuse"
	}
	parts := make([]string, 0, len(g.Refused))
	for _, name := range slices.Sorted(maps.Keys(g.Refused)) {
		parts = append(parts, fmt.Sprintf("%s %d", name, g.Refused[name]))
	}
	return fmt.Sprintf("%s, %s: %s", g.Mode, verb, strings.Join(parts, ", "))
}

func listLine(l agent.ListStatus) string {
	line := fmt.Sprintf("%d ranges", l.Entries)
	switch {
	case l.Missing:
		line += ", copy MISSING or unreadable"
	case l.Refresh > 0:
		line += fmt.Sprintf(", copies %v old (refresh %v)", l.Age.Round(time.Minute), l.Refresh)
	}
	if l.Failed {
		line += ", last resolution FAILED"
	}
	return line
}

func countersLine(counters map[string]uint64) string {
	names := make([]string, 0, len(counters))
	for name, n := range counters {
		if n > 0 {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return "none yet"
	}
	slices.Sort(names)
	parts := make([]string, 0, len(names))
	for _, name := range names {
		parts = append(parts, fmt.Sprintf("%s %d", name, counters[name]))
	}
	return strings.Join(parts, ", ")
}

// runTest explains what the node does with a destination, sending it nothing.
// A domain is resolved the way the node's processes resolve it — through the
// vnm resolver while it is up, which also puts it into the domain sets.
func runTest(ctx context.Context, paths app.Paths, target string) error {
	addrs, err := targetAddrs(ctx, target)
	if err != nil {
		return err
	}
	in := paths.Inspector()
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer w.Flush()
	for _, addr := range addrs {
		ex, err := in.Explain(ctx, addr)
		if err != nil {
			return err
		}
		fmt.Fprintf(w, "%s\t%s\t⇒ %s\n", addr, matchesLine(ex), outcomeLine(ex))
		if ex.Outcome != inspect.OutcomeUnmanaged {
			fmt.Fprintf(w, "\tinbound from it\t⇒ %s\n", inboundLine(ex))
		}
	}
	return nil
}

// inboundLine is what the guard does with a new connection from the address.
func inboundLine(ex inspect.Explanation) string {
	switch r := ex.Guarded; {
	case r == nil && ex.Exempt:
		return "ALLOW (exempt)"
	case r == nil:
		return "ALLOW"
	case ex.GuardObserve:
		return fmt.Sprintf("ALLOW (guard observe; enforce would refuse, list %s)", r.List)
	case r.Reject:
		return fmt.Sprintf("REJECT (list %s)", r.List)
	default:
		return fmt.Sprintf("DROP (list %s)", r.List)
	}
}

func targetAddrs(ctx context.Context, target string) ([]netip.Addr, error) {
	if addr, err := netip.ParseAddr(target); err == nil {
		return []netip.Addr{addr}, nil
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", target)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", target, err)
	}
	if len(addrs) == 0 {
		return nil, errors.New("no addresses")
	}
	parts := make([]string, 0, len(addrs))
	for i, a := range addrs {
		addrs[i] = a.Unmap()
		parts = append(parts, addrs[i].String())
	}
	fmt.Printf("%s: %s\n", target, strings.Join(parts, ", "))
	return addrs, nil
}

func matchesLine(ex inspect.Explanation) string {
	if ex.Outcome == inspect.OutcomeUnmanaged {
		return "-"
	}
	parts := make([]string, 0, len(ex.Matches)+1)
	if ex.Exempt {
		parts = append(parts, "exempt")
	}
	for _, m := range ex.Matches {
		parts = append(parts, fmt.Sprintf("%s (%s)", m.List, m.Set))
	}
	if len(parts) == 0 {
		return "no list"
	}
	return strings.Join(parts, ", ")
}

func outcomeLine(ex inspect.Explanation) string {
	line := outcomeName(ex.Would, ex.Exit)
	switch {
	case ex.Outcome == inspect.OutcomeUnmanaged:
		return "DIRECT (the vnm table is absent)"
	case ex.Observe && ex.Would != inspect.OutcomeDirect:
		return "DIRECT (observe; enforce would " + line + ")"
	}
	return line
}

func outcomeName(o inspect.Outcome, exit *netstate.Exit) string {
	switch o {
	case inspect.OutcomeDirect:
		return "DIRECT"
	case inspect.OutcomeBlock:
		return "BLOCK"
	case inspect.OutcomeExit:
		return fmt.Sprintf("EXIT dev %s (mark 0x%x, table %d)", exit.Iface, netstate.ExitMark(exit.Slot), netstate.ExitTable(exit.Slot))
	case inspect.OutcomeRefused:
		return fmt.Sprintf("REFUSED (exit dev %s declared dead)", exit.Iface)
	default:
		return "UNKNOWN"
	}
}
