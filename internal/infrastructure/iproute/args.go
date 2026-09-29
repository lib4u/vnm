// Package iproute writes the routing part of the desired state — policy rules
// and exit routes — through the ip(8) tool.
package iproute

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/lib4u/vnm/internal/domain/netstate"
)

// RuleArgs returns the ip arguments that add or delete a policy rule, without
// the leading "rule add"/"rule del" verb. They name every selector the rule
// has and nothing more: the kernel deletes the first rule of the priority that
// matches what a deletion names, so a selector left out — or a zero mark sent
// for a rule without one — matches any rule there, the agent's own included.
func RuleArgs(r netstate.IPRule) []string {
	args := []string{"priority", strconv.Itoa(r.Priority)}
	if r.Mark != 0 || r.Mask != 0 {
		args = append(args, "fwmark", MarkArg(r))
	}
	switch r.Action {
	case netstate.RuleLookup:
		args = append(args, "lookup", strconv.Itoa(r.Table))
	case netstate.RuleUnreachable:
		args = append(args, "unreachable")
	case netstate.RuleBlackhole:
		args = append(args, "blackhole")
	case netstate.RuleProhibit:
		args = append(args, "prohibit")
	default:
		// A foreign rule's action the domain cannot express is in Extra.
		if r.Extra == "" {
			panic(fmt.Sprintf("iproute: rule action %d is not set", r.Action))
		}
	}
	return append(args, strings.Fields(r.Extra)...)
}

// MarkArg is the fwmark argument of a rule, with its mask when it has one. A
// rule without a mask compares the whole mark, so for the kernel it is a
// different rule from one with a mask — which is what lets a foreign rule be
// deleted without touching the agent's rule at the same priority.
func MarkArg(r netstate.IPRule) string {
	mark := fmt.Sprintf("0x%x", r.Mark)
	if r.Mask != 0 {
		mark += fmt.Sprintf("/0x%x", r.Mask)
	}
	return mark
}

// RouteArgs returns the ip arguments that set or delete a default route in an
// exit table, without the leading "route replace"/"route del" verb. The type
// is always named — a deletion without one matches a route of any type — and
// the metric, device and whatever else tells the route apart whenever the
// route has them.
func RouteArgs(r netstate.Route) []string {
	typ := string(r.Type)
	if r.Type == netstate.RouteUnicast {
		typ = "unicast"
	}
	args := []string{typ, "default", "table", strconv.Itoa(r.Table)}
	if r.Metric != 0 {
		args = append(args, "metric", strconv.Itoa(r.Metric))
	}
	if r.Dev != "" {
		args = append(args, "dev", r.Dev)
	}
	return append(args, strings.Fields(r.Extra)...)
}
