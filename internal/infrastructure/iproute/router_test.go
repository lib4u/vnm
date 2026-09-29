package iproute_test

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/lib4u/vnm/internal/domain/netstate"
	"github.com/lib4u/vnm/internal/infrastructure/iproute"
	"github.com/lib4u/vnm/internal/infrastructure/runner"
)

// fakeIP answers every ip invocation with one captured output and records the
// arguments of each call.
type fakeIP struct {
	out   string
	calls []string
}

func (f *fakeIP) Run(_ context.Context, cmd runner.Command) (string, error) {
	f.calls = append(f.calls, strings.Join(cmd.Args, " "))
	return f.out, nil
}

// captured returns the output of `ip -j …` captured in a network namespace.
func captured(t *testing.T, name string) *fakeIP {
	t.Helper()
	out, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return &fakeIP{out: string(out)}
}

// The listing holds the agent's two rules and a foreign rule next to each of
// them, one per kind of selector ip prints.
func TestRulesParsesEverySelector(t *testing.T) {
	ip := captured(t, "rules.json")
	got, err := iproute.NewRouter(ip).Rules(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ours := netstate.ExitRules(0)
	want := []netstate.IPRule{
		ours[0],
		{Priority: 1000, Mark: 0xca6c, Mask: 0xffff, Action: netstate.RuleLookup, Table: 51820, Extra: "iif eth9"},
		ours[1],
		{Priority: 1001, Extra: "iif lo nop"},
		{Priority: 1002, Action: netstate.RuleLookup, Table: 254, Extra: "not from 10.0.0.0/8 to 192.0.2.1 tos 0x10 " +
			"oif eth0 uidrange 0-0 ipproto tcp sport 80 dport 1000-2000 suppress_prefixlength 0 protocol static"},
		{Priority: 1003, Mask: 0xff, Extra: "goto 1100"},
		{Priority: 1004, Action: netstate.RuleLookup, Table: 100, Extra: "fwmark 0/0xffffffff suppress_ifgroup 5 realms 3/4"},
		{Priority: 1005, Extra: "dscp CS1/0x38 l3mdev dport 53/0xff"},
		{Priority: 1006, Mark: 0xca6c, Action: netstate.RuleBlackhole},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("Rules =\n%+v\nwant\n%+v", got, want)
	}
}

// A deletion names every selector of the rule and no mark the rule does not
// have: `fwmark 0x0` would match any mark, the agent's rule included.
func TestDeleteRuleNamesEverySelector(t *testing.T) {
	tests := []struct {
		rule netstate.IPRule
		want string
	}{
		{netstate.IPRule{Priority: 1001, Extra: "iif lo nop"}, "rule del priority 1001 iif lo nop"},
		{netstate.IPRule{Priority: 1003, Mask: 0xff, Extra: "goto 1100"}, "rule del priority 1003 fwmark 0x0/0xff goto 1100"},
		{
			netstate.IPRule{Priority: 1000, Mark: 0xca6c, Mask: 0xffff, Action: netstate.RuleLookup, Table: 51820, Extra: "iif eth9"},
			"rule del priority 1000 fwmark 0xca6c/0xffff lookup 51820 iif eth9",
		},
		{netstate.ExitRules(0)[1], "rule del priority 1001 fwmark 0xca6c/0xffff unreachable"},
	}
	for _, tt := range tests {
		ip := &fakeIP{}
		if err := iproute.NewRouter(ip).DeleteRule(context.Background(), tt.rule); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(ip.calls, []string{tt.want}) {
			t.Errorf("DeleteRule(%+v) ran %q, want %q", tt.rule, ip.calls, tt.want)
		}
	}
}

// An attribute the adapter does not know could be what tells a foreign rule
// from the agent's; deleting without it could take the wrong rule.
func TestRulesRejectsUnknownAttribute(t *testing.T) {
	ip := &fakeIP{out: `[{"priority":1001,"src":"all","fwmark":"0xca6c","fwmask":"0xffff","action":"unreachable","frobnicate":1}]`}
	if _, err := iproute.NewRouter(ip).Rules(context.Background()); err == nil || !strings.Contains(err.Error(), "frobnicate") {
		t.Fatalf("Rules err = %v, want one naming the unknown attribute", err)
	}
}

// Rules outside the owned range are not parsed: whatever they carry is none
// of the agent's business.
func TestRulesIgnoresForeignRangeAttributes(t *testing.T) {
	ip := &fakeIP{out: `[{"priority":88,"src":"all","frobnicate":1,"table":"main"}]`}
	if rules, err := iproute.NewRouter(ip).Rules(context.Background()); err != nil || len(rules) != 0 {
		t.Fatalf("Rules = %+v, %v", rules, err)
	}
}

// conf is an iproute2 configuration that names two of the owned tables, one in
// the main file and one in a drop-in — the configuration the named listings in
// testdata were captured under.
var conf = fstest.MapFS{
	"etc/iproute2/rt_tables":              {Data: []byte("# reserved\n255\tlocal\n254\tmain\n51820 warp\n")},
	"etc/iproute2/rt_tables.d/exits.conf": {Data: []byte("0xca6d exit1 # slot 1\n")},
}

// The owned tables are recognised under any name the configuration gives
// them; a name it does not define is a foreign table.
func TestRulesResolveTableNames(t *testing.T) {
	ours := netstate.ExitRules(0)
	slot1 := netstate.ExitRules(1)[0]
	tests := []struct {
		conf fstest.MapFS
		want netstate.IPRule
	}{
		{conf, slot1},
		{fstest.MapFS{"usr/share/iproute2/rt_tables": conf["etc/iproute2/rt_tables"]}, netstate.IPRule{
			Priority: 1002, Mark: 0xca6d, Mask: 0xffff, Extra: "lookup exit1",
		}},
	}
	for _, tt := range tests {
		ip := captured(t, "rules_named.json")
		got, err := iproute.NewRouter(ip, iproute.WithConfigRoot(tt.conf)).Rules(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		lookup51829 := netstate.IPRule{Priority: 1003, Mark: 0xca6d, Mask: 0xffff, Action: netstate.RuleLookup, Table: 51829}
		if want := []netstate.IPRule{ours[0], ours[1], tt.want, lookup51829}; !slices.Equal(got, want) {
			t.Errorf("Rules =\n%+v\nwant\n%+v", got, want)
		}
	}
}

// Every default route of the owned tables is read with what tells it apart
// from the agent's: its type, metric, TOS, gateway, nexthops.
func TestRoutesTellForeignFromOurs(t *testing.T) {
	ip := captured(t, "routes.json")
	got, err := iproute.NewRouter(ip, iproute.WithConfigRoot(conf)).Routes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []netstate.Route{
		{Table: 51820, Dev: "warp", Extra: "tos 0x10"},
		{Table: 51820, Dev: "warp"},
		{Table: 51820, Metric: 5, Dev: "eth0", Extra: "proto static src 10.0.0.2 via 10.0.0.1"},
		{Table: 51820, Type: "unreachable", Metric: 10},
		{Table: 51821, Type: "blackhole"},
		{Table: 51821, Metric: 7, Extra: "nexthop via 10.0.0.1 dev eth0 weight 2 nexthop via 10.1.0.1 dev eth1 weight 1"},
		{Table: 51822, Extra: "nhid 3"},
		{Table: 51823, Dev: "eth0", Extra: "via 10.0.0.1"},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("Routes =\n%+v\nwant\n%+v", got, want)
	}
}

func TestDeleteRouteIsExact(t *testing.T) {
	tests := []struct {
		route netstate.Route
		want  string
	}{
		{netstate.Route{Table: 51820, Type: "unreachable", Metric: 10}, "route del unreachable default table 51820 metric 10"},
		{netstate.Route{Table: 51821, Type: "blackhole"}, "route del blackhole default table 51821"},
		{netstate.Route{Table: 51820, Metric: 20, Dev: "eth0"}, "route del unicast default table 51820 metric 20 dev eth0"},
		{netstate.Route{Table: 51820, Dev: "warp", Extra: "tos 0x10"}, "route del unicast default table 51820 dev warp tos 0x10"},
		{netstate.Route{Table: 51822, Extra: "nhid 3"}, "route del unicast default table 51822 nhid 3"},
	}
	for _, tt := range tests {
		ip := &fakeIP{}
		if err := iproute.NewRouter(ip).DeleteRoute(context.Background(), tt.route); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(ip.calls, []string{tt.want}) {
			t.Errorf("DeleteRoute(%+v) ran %q, want %q", tt.route, ip.calls, tt.want)
		}
	}
}

// A multipath default route and a nexthop group keep their devices in the
// nexthops.
func TestUplinksFromNexthops(t *testing.T) {
	tests := []struct {
		file string
		want []string
	}{
		{"uplinks_multipath.json", []string{"eth0", "eth1"}},
		{"uplinks_nhid.json", []string{"eth0", "eth1", "eth2"}},
	}
	for _, tt := range tests {
		got, err := iproute.NewRouter(captured(t, tt.file)).Uplinks(context.Background())
		if err != nil || !slices.Equal(got, tt.want) {
			t.Errorf("%s: Uplinks = %v, %v; want %v", tt.file, got, err, tt.want)
		}
	}
}
