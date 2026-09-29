package planner_test

import (
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/lib4u/vnm/internal/domain/netstate"
	"github.com/lib4u/vnm/internal/domain/policy"
	"github.com/lib4u/vnm/internal/testsupport"
	"github.com/lib4u/vnm/internal/usecase/planner"
)

func input() planner.Input {
	in := testsupport.PlanInput()
	in.Listen = netstate.Ports{TCP: []uint16{443, 22, 443}, UDP: []uint16{8851}}
	return in
}

func plan(t *testing.T, in planner.Input) netstate.State {
	t.Helper()
	state, err := planner.Plan(in)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	return state
}

func decisionFor(t *testing.T, s netstate.State, set string) netstate.Decision {
	t.Helper()
	for _, d := range s.Classify.Decisions {
		if d.Set == set {
			return d
		}
	}
	t.Fatalf("no decision for set %q in %+v", set, s.Classify.Decisions)
	return netstate.Decision{}
}

func TestPlanRoutesListThroughExit(t *testing.T) {
	s := plan(t, input())

	if got := decisionFor(t, s, "ru_ip_4").Verdict; got != netstate.VerdictExit(0) {
		t.Fatalf("ru_ip_4 verdict = %+v, want exit 0", got)
	}
	if got := decisionFor(t, s, "ru_suffix_d4").Verdict; got != netstate.VerdictExit(0) {
		t.Fatalf("ru_suffix_d4 verdict = %+v, want exit 0", got)
	}
	want := netstate.ExitRules(0)
	if !reflect.DeepEqual(s.Rules, want[:]) {
		t.Fatalf("rules = %+v, want %+v", s.Rules, want)
	}
	if len(s.Routes) != 1 || s.Routes[0] != (netstate.Route{Table: 51820, Dev: "warp"}) {
		t.Fatalf("routes = %+v", s.Routes)
	}
}

// Health must never change the classification or the rules — otherwise every
// health flap would rewrite the ruleset. A dead exit is only listed as dead;
// an exit without an interface also loses its route, so its unreachable rule
// fails the traffic with no agent involved (I-2).
func TestPlanExitHealth(t *testing.T) {
	healthy := plan(t, input())
	if len(healthy.Health.DeadSlots) != 0 || len(healthy.Routes) != 1 {
		t.Fatalf("healthy: dead %v routes %+v", healthy.Health.DeadSlots, healthy.Routes)
	}

	tests := []struct {
		name       string
		status     planner.ExitStatus
		wantRoutes int
	}{
		{"dead but present", planner.ExitStatus{Present: true}, 1},
		{"interface gone", planner.ExitStatus{}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := input()
			in.Exits = map[string]planner.ExitStatus{"warp": tt.status}
			got := plan(t, in)

			if !reflect.DeepEqual(got.Health.DeadSlots, []int{0}) {
				t.Errorf("dead slots = %v, want [0]", got.Health.DeadSlots)
			}
			if len(got.Routes) != tt.wantRoutes {
				t.Errorf("routes = %+v, want %d", got.Routes, tt.wantRoutes)
			}
			if !reflect.DeepEqual(got.Rules, healthy.Rules) || !reflect.DeepEqual(got.Classify, healthy.Classify) {
				t.Error("rules or classification changed with health")
			}
		})
	}
}

// IPv6 does not go through exits yet, and the node's native IPv6 is as public
// as its IPv4, so an IPv6 destination bound for an exit is blocked (ТЗ §3.5).
func TestPlanBlocksIPv6BoundForExit(t *testing.T) {
	s := plan(t, input())
	for _, set := range []string{"ru_ip_6", "ru_suffix_d6"} {
		if got := decisionFor(t, s, set).Verdict; got != netstate.VerdictBlock {
			t.Fatalf("%s verdict = %+v, want block", set, got)
		}
	}
}

// An empty set for a list with address sources would let its destinations out
// directly. The plan must fail instead of leaking.
func TestPlanRefusesUnresolvedList(t *testing.T) {
	in := input()
	in.Ranges = map[string][]netip.Prefix{}
	if _, err := planner.Plan(in); !errors.Is(err, planner.ErrUnresolvedList) {
		t.Fatalf("want ErrUnresolvedList, got %v", err)
	}
}

func TestPlanExemptsEndpointsAndLocalRanges(t *testing.T) {
	s := plan(t, input())
	exempt := func(addr netip.Addr) bool {
		for _, p := range s.Classify.Exempt {
			if p.Contains(addr) {
				return true
			}
		}
		return false
	}
	for _, addr := range []netip.Addr{
		testsupport.WarpEndpoint.Addr(),        // or the exit tunnel would route into itself
		testsupport.Management.Addr(),          // configured
		netip.MustParseAddr("10.77.1.2"),       // private
		netip.MustParseAddr("127.0.0.1"),       // loopback
		netip.MustParseAddr("fe80::1"),         // link-local
		netip.MustParseAddr("100.64.0.1"),      // CGNAT
		netip.MustParseAddr("239.255.255.250"), // multicast
	} {
		if !exempt(addr) {
			t.Errorf("%v is not exempt", addr)
		}
	}
	if exempt(testsupport.RUSite) || exempt(testsupport.ForeignSite) {
		t.Error("an internet destination is exempt")
	}
}

func TestPlanObserveKeepsDecisions(t *testing.T) {
	in := input()
	in.Policy.Mode = policy.ModeObserve
	s := plan(t, in)
	if !s.Classify.Observe {
		t.Fatal("observe flag not set")
	}
	// Observe counts what enforce would do, so the decisions are the same.
	if !reflect.DeepEqual(s.Classify.Decisions, plan(t, input()).Classify.Decisions) {
		t.Fatal("observe decisions differ from enforce")
	}
}

func TestPlanOffOwnsNothing(t *testing.T) {
	in := input()
	in.Policy.Mode = policy.ModeOff
	in.Policy.Guard.Mode = policy.ModeOff
	if s := plan(t, in); !reflect.DeepEqual(s, netstate.State{}) {
		t.Fatalf("off state = %+v", s)
	}
}

// The guard is planned as it asks, and the egress likewise: `mode: off`
// lifts the destination policy, never the guard (G-4, G-7).
func TestPlanGuard(t *testing.T) {
	s := plan(t, input())
	want := netstate.Guard{Rules: []netstate.GuardRule{
		{List: "scanners", Set: "scanners_4", Family: netstate.IPv4, Log: true, Counter: "g_scanners_4"},
		{List: "scanners", Set: "scanners_6", Family: netstate.IPv6, Log: true, Counter: "g_scanners_6"},
	}}
	if !reflect.DeepEqual(s.Guard, want) {
		t.Fatalf("guard = %+v", s.Guard)
	}

	in := input()
	in.Policy.Mode = policy.ModeOff
	s = plan(t, in)
	switch {
	case s.Empty():
		t.Fatal("egress off removed the guard")
	case s.Classify.Classifies() || len(s.Classify.Exits) > 0 || len(s.Rules) > 0 || s.DNS.Enabled():
		t.Fatalf("egress off still classifies: %+v", s)
	case !reflect.DeepEqual(s.Guard, want):
		t.Fatalf("guard = %+v", s.Guard)
	}

	in = input()
	in.Policy.Guard.Mode = policy.ModeObserve
	if s := plan(t, in); !s.Guard.Observe {
		t.Fatal("observe flag not set")
	}
	in.Policy.Guard.Mode = policy.ModeOff
	if s := plan(t, in); s.Guard.Active() {
		t.Fatalf("guard off still planned: %+v", s.Guard)
	}
}

// A guard list that did not resolve guards nothing and blocks nothing else.
func TestPlanGuardFailsOpenPerList(t *testing.T) {
	in := input()
	delete(in.Ranges, "scanners")
	s := plan(t, in)
	for _, set := range s.Classify.Sets {
		if strings.HasPrefix(set.Name, "scanners_") && len(set.Prefixes) != 0 {
			t.Fatalf("unresolved guard list has ranges: %+v", set)
		}
	}
	if len(s.Guard.Rules) != 2 || !s.Classify.Classifies() {
		t.Fatalf("state = %+v", s)
	}
}

// A list both parts use is one set, strict as the egress needs it.
func TestPlanGuardSharesEgressSets(t *testing.T) {
	in := input()
	in.Policy.Guard.Rules[0].Lists = []string{"ru_ip"}
	s := plan(t, in)
	n := 0
	for _, set := range s.Classify.Sets {
		if set.Name == "ru_ip_4" {
			n++
		}
	}
	if n != 1 || s.Guard.Rules[0].Set != "ru_ip_4" {
		t.Fatalf("sets %+v guard %+v", s.Classify.Sets, s.Guard)
	}
	delete(in.Ranges, "ru_ip")
	if _, err := planner.Plan(in); !errors.Is(err, planner.ErrUnresolvedList) {
		t.Fatalf("shared list unresolved: %v", err)
	}
}

func TestPlanDetectedUplinkUsedWhenNotConfigured(t *testing.T) {
	in := input()
	in.Policy.Uplinks = nil
	in.Uplinks = []string{"eth0"}
	if got := plan(t, in).Classify.Uplinks; !reflect.DeepEqual(got, []string{"eth0"}) {
		t.Fatalf("uplinks = %v", got)
	}

	in.Uplinks = nil
	if _, err := planner.Plan(in); !errors.Is(err, policy.ErrInvalid) {
		t.Fatalf("no uplink: want ErrInvalid, got %v", err)
	}
}

func TestPlanNormalizesListenPorts(t *testing.T) {
	got := plan(t, input()).Classify.Listen
	want := netstate.Ports{TCP: []uint16{22, 443}, UDP: []uint16{8851}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("listen = %+v, want %+v", got, want)
	}
}

func TestListSizes(t *testing.T) {
	got := planner.ListSizes(plan(t, input()))
	want := map[string]int{"ru_ip": len(testsupport.RURanges), "scanners": len(testsupport.ScannerRanges)}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ListSizes = %v, want %v", got, want)
	}

	// A list whose own name ends like a family suffix keeps its name.
	in := input()
	in.Policy.Lists[0].Name = "net_6"
	in.Policy.Rules[0].Lists[0] = "net_6"
	in.Ranges = map[string][]netip.Prefix{"net_6": testsupport.RURanges}
	if got := planner.ListSizes(plan(t, in)); got["net_6"] != len(testsupport.RURanges) {
		t.Fatalf("ListSizes = %v, want net_6: %d", got, len(testsupport.RURanges))
	}
}

func TestPlanResolver(t *testing.T) {
	s := plan(t, input())
	want := netstate.DNSState{
		Port:      5353,
		Upstreams: []netip.AddrPort{testsupport.DNSUpstream},
		// The list goes through an exit, which carries IPv4 only: its
		// domains are answered without IPv6 addresses.
		Sets: []netstate.DomainSet{{Set4: "ru_suffix_d4", Set6: "ru_suffix_d6", Domains: testsupport.RUSuffixes, NoAAAA: true}},
	}
	if !reflect.DeepEqual(s.DNS, want) || s.Classify.DNSPort != 5353 {
		t.Fatalf("dns = %+v, port %d", s.DNS, s.Classify.DNSPort)
	}
	// In observe nothing is blocked, so the answers stay as they are.
	observe := input()
	observe.Policy.Mode = policy.ModeObserve
	if s := plan(t, observe); s.DNS.Sets[0].NoAAAA {
		t.Fatal("observe drops IPv6 addresses")
	}
	// The resolver's own queries must not be classified.
	upstream := testsupport.DNSUpstream.Addr()
	if !slices.ContainsFunc(s.Classify.Exempt, func(p netip.Prefix) bool { return p.Contains(upstream) }) {
		t.Fatal("dns upstream is not exempt")
	}

	// A domain list without domains would leave its sets silently empty.
	in := input()
	in.Domains = nil
	if _, err := planner.Plan(in); !errors.Is(err, planner.ErrUnresolvedList) {
		t.Fatalf("no domains: want ErrUnresolvedList, got %v", err)
	}
}

func TestPlanWithoutDomainListsRunsNoResolver(t *testing.T) {
	in := input()
	in.Policy.Lists = slices.DeleteFunc(in.Policy.Lists, func(l policy.List) bool { return l.Name == "ru_suffix" })
	in.Policy.Rules[0].Lists = []string{"ru_ip"}
	if s := plan(t, in); s.DNS.Enabled() || s.Classify.DNSPort != 0 {
		t.Fatalf("resolver planned without domain lists: %+v", s.DNS)
	}
}
