package iproute

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/lib4u/vnm/internal/domain/netstate"
)

// ruleEntry is one entry of `ip -j rule show`, attribute by attribute: ip
// prints only the attributes a rule has, and a foreign rule is deleted exactly
// only when the deletion names every one of them.
type ruleEntry map[string]json.RawMessage

func (e ruleEntry) priority() (int, error) {
	var p int
	if err := json.Unmarshal(e["priority"], &p); err != nil {
		return 0, fmt.Errorf("priority: %w", err)
	}
	return p, nil
}

// ruleState are the attributes ip prints about a rule's state rather than what
// it matches: an interface that does not exist (yet), a goto whose target is
// gone. No ip argument sets them.
var ruleState = []string{"iif_detached", "oif_detached", "unresolved"}

// ruleSelectors turn the attributes the domain does not model back into ip rule
// arguments, in a fixed order — ip takes them in any. An attribute ip prints as
// a flag becomes its keyword alone.
var ruleSelectors = []struct {
	// arg is the ip keyword, key the attribute holding its value.
	arg, key string
	// all is the value ip prints for a selector that matches everything.
	all string
	// part is an attribute joined to the value with sep — a prefix length,
	// a mask, the end of a range — unless it holds full, its default.
	part, sep, full string
}{
	{arg: "not", key: "not"},
	{arg: "from", key: "src", all: "all", part: "srclen", sep: "/"},
	{arg: "to", key: "dst", part: "dstlen", sep: "/"},
	{arg: "tos", key: "tos"},
	{arg: "dscp", key: "dscp", part: "dscp_mask", sep: "/", full: "0x3f"},
	{arg: "iif", key: "iif"},
	{arg: "oif", key: "oif"},
	{arg: "l3mdev", key: "l3mdev"},
	{arg: "uidrange", key: "uid_start", part: "uid_end", sep: "-"},
	{arg: "ipproto", key: "ipproto"},
	{arg: "sport", key: "sport", part: "sport_mask", sep: "/", full: "0xffff"},
	{arg: "sport", key: "sport_start", part: "sport_end", sep: "-"},
	{arg: "dport", key: "dport", part: "dport_mask", sep: "/", full: "0xffff"},
	{arg: "dport", key: "dport_start", part: "dport_end", sep: "-"},
	{arg: "tun_id", key: "tun_id"},
	{arg: "suppress_prefixlength", key: "suppress_prefixlen"},
	{arg: "suppress_ifgroup", key: "suppress_ifgroup"},
	// ip prints the source realm only when there is one.
	{arg: "realms", key: "flow_from", part: "flow_to", sep: "/"},
	{arg: "realms", key: "flow_to"},
	{arg: "goto", key: "goto"},
	{arg: "nop", key: "nop"},
	{arg: "protocol", key: "protocol"},
}

// parseRule maps an ip rule entry to the domain. What the domain cannot
// express goes into Extra, so that a foreign rule in the owned range is never
// taken for the agent's and is deleted exactly. An attribute this adapter does
// not know is an error: a deletion without it could hit the agent's own rule.
func parseRule(e ruleEntry, tables *tableNames) (netstate.IPRule, error) {
	priority, err := e.priority()
	if err != nil {
		return netstate.IPRule{}, err
	}
	out := netstate.IPRule{Priority: priority}
	a := attrs{m: maps.Clone(e)}
	a.drop("priority")
	a.drop(ruleState...)

	var extra []string
	if _, ok := a.m["fwmark"]; ok {
		out.Mark, out.Mask = a.mark("fwmark"), a.mark("fwmask")
		if out.Mark == 0 && out.Mask == 0 {
			// ip prints "fwmark 0" alone for a zero mark compared whole,
			// which the domain cannot tell from no mark at all.
			extra = append(extra, "fwmark", "0/0xffffffff")
		}
	}
	if table, ok := a.take("table"); ok {
		id, known, err := tables.id(table)
		if err != nil {
			return netstate.IPRule{}, err
		}
		if known {
			out.Action, out.Table = netstate.RuleLookup, id
		} else {
			extra = append(extra, "lookup", table)
		}
	}
	if action, ok := a.take("action"); ok {
		switch action {
		case "unreachable":
			out.Action = netstate.RuleUnreachable
		case "blackhole":
			out.Action = netstate.RuleBlackhole
		case "prohibit":
			out.Action = netstate.RuleProhibit
		default:
			return netstate.IPRule{}, fmt.Errorf("unsupported action %q", action)
		}
	}
	for _, s := range ruleSelectors {
		v, ok := a.take(s.key)
		if !ok || (s.all != "" && v == s.all) {
			continue
		}
		if part, ok := a.take(s.part); ok && part != s.full {
			v += s.sep + part
		}
		extra = append(extra, s.arg)
		if v != "" {
			extra = append(extra, v)
		}
	}
	out.Extra = strings.Join(extra, " ")

	if a.err != nil {
		return netstate.IPRule{}, a.err
	}
	if len(a.m) > 0 {
		return netstate.IPRule{}, fmt.Errorf("unsupported attributes %q", slices.Sorted(maps.Keys(a.m)))
	}
	if out.Action == netstate.RuleActionUnknown && out.Extra == "" {
		return netstate.IPRule{}, errors.New("no action")
	}
	return out, nil
}

// attrs hands out the attributes of one entry, removing each one taken: what
// is left at the end is an attribute nobody knows. The first malformed value
// is kept in err.
type attrs struct {
	m   map[string]json.RawMessage
	err error
}

// take removes an attribute and returns its value the way ip takes it back: a
// string unquoted, a number as printed, a flag as "".
func (a *attrs) take(key string) (string, bool) {
	raw, ok := a.m[key]
	if !ok {
		return "", false
	}
	delete(a.m, key)
	switch {
	case string(raw) == "null":
		return "", true
	case strings.HasPrefix(string(raw), `"`):
		var s string
		a.fail(key, json.Unmarshal(raw, &s))
		return s, true
	default:
		return string(raw), true
	}
}

func (a *attrs) drop(keys ...string) {
	for _, k := range keys {
		delete(a.m, k)
	}
}

// mark takes a mark as ip prints it — hex with a 0x prefix, or a bare 0; a
// missing one is zero.
func (a *attrs) mark(key string) uint32 {
	s, ok := a.take(key)
	if !ok {
		return 0
	}
	v, err := strconv.ParseUint(s, 0, 32)
	a.fail(key, err)
	return uint32(v)
}

func (a *attrs) fail(what string, err error) {
	if err != nil && a.err == nil {
		a.err = fmt.Errorf("%s: %w", what, err)
	}
}
