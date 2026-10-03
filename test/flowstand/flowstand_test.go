// Package flowstand is the flow-model stand of tests.md §1: the rules the agent
// generates, loaded into a real kernel, with real traffic in both directions.
//
// It exists because the whole design rests on one claim — that a connection the
// node opens can be told apart from a reply to a connection a client opened. If
// that claim is wrong, the policy reroutes replies to clients into the exit and
// cuts the node off from its users. The stand checks it before any agent code
// is trusted with a node.
package flowstand

import (
	"bufio"
	"cmp"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/lib4u/vnm/internal/domain/netstate"
	"github.com/lib4u/vnm/internal/domain/policy"
	"github.com/lib4u/vnm/internal/infrastructure/iproute"
	"github.com/lib4u/vnm/internal/infrastructure/nftables"
	"github.com/lib4u/vnm/internal/infrastructure/resolver"
	"github.com/lib4u/vnm/internal/testsupport"
	"github.com/lib4u/vnm/internal/usecase/planner"
)

// Addresses as seen by the far side; they must match stand.sh.
const (
	viaUplink = "src=192.0.2.100"
	viaExit   = "src=198.18.0.2"
	ruClient  = "src=198.51.100.50"
	// What the node's services see of the stand's sources.
	fromForeign = "src=203.0.113.10"
	fromScanner = "src=203.0.113.66"
	fromMgmt    = "src=192.0.2.200"
	// IPv6.
	viaUplink6   = "src=2001:db8:1::100"
	fromForeign6 = "src=2001:db8:200::10"
	fromScanner6 = "src=2001:db8:666::66"
)

// guarded are the guard's scenarios with the guard in enforce, whatever the
// egress does (G-7).
var guarded = []expectation{
	{"G-0", fromForeign, "a source outside the guard's lists reaches the node"},
	{"G-1", "err=timeout", "G-1: a listed source never reaches the node's TCP port"},
	{"G-1u", "err=timeout", "G-1: a listed source never reaches the node's UDP port"},
	{"G-1d", "err=timeout", "G-1: a listed source never reaches a container behind DNAT"},
	{"G-0d", fromForeign, "the container behind DNAT is reachable from other sources"},
	{"G-2", viaUplink, "G-2: the node's own connection to a listed address gets its replies"},
	{"G-3", fromMgmt, "G-3: an exempt source passes even when listed"},
	{"G-5", viaUplink, "G-5: a downstream client's connection to a listed address is not the guard's business"},
	{"G-0v6", fromForeign6, "an IPv6 source outside the guard's lists reaches the node"},
	{"G-1v6", "err=timeout", "G-1: a listed IPv6 source never reaches the node"},
}

// observed are the guard's scenarios with the guard in observe: nothing is
// refused, and what enforce lets through goes through the same way.
var observed = []expectation{
	{"G-0", fromForeign, "observe: an unlisted source reaches the node"},
	{"G-1", fromScanner, "G-6: the guard in observe refuses nothing"},
	{"G-1d", fromScanner, "G-6: the guard in observe refuses nothing"},
	{"G-1v6", fromScanner6, "G-6: the guard in observe refuses nothing, IPv6 included"},
	{"G-2", viaUplink, "G-2 holds in observe"},
	{"G-3", fromMgmt, "G-3 holds in observe"},
}

// p2pRefused are the p2p scenarios with the part in enforce, whatever the
// egress and the guard do (p2p ТЗ §8).
var p2pRefused = []expectation{
	// A local UDP packet dropped on the output hook fails its send at once:
	// the proxy learns the flow is closed instead of waiting on it.
	{"P-1", "err=EPERM", "P-1: a uTP ST_SYN from the node never leaves"},
	{"P-1t", "err=timeout", "P-1: a uTP ST_SYN from a tunnel client never leaves"},
	{"P-2", "err=EPERM", "P-1: a DHT query from the node never leaves"},
	{"P-2t", "err=timeout", "P-1: a DHT query from a tunnel client never leaves"},
	{"P-3", "err=EPERM", "P-1: a UDP tracker connect never leaves"},
	{"P-4", "err=timeout", "P-1: a plaintext BitTorrent handshake from the node never leaves"},
	{"P-4t", "err=timeout", "P-1: a plaintext BitTorrent handshake from a tunnel client never leaves"},
}

// p2pPassed are the scenarios that must pass whatever the p2p part's mode:
// packets that only resemble a signature, and the excluded ports (P-4).
var p2pPassed = []expectation{
	{"P-N1", viaUplink, "TURN ChannelData shares the uTP SYN's first byte, not its fields"},
	{"P-N2", viaUplink, "a STUN binding request is not a signature"},
	{"P-N3", viaUplink, "plain UDP to a BitTorrent port passes"},
	{"P-N4", viaUplink, "P-4: UDP 443 is never looked at, whatever it carries"},
	{"P-N5", viaUplink, "plain TCP to a BitTorrent port passes"},
}

// p2pAllowed are the p2p scenarios with the part in observe or off: nothing
// is refused.
var p2pAllowed = []expectation{
	{"P-1", viaUplink, "P-6: the p2p part in observe or off refuses nothing"},
	{"P-1t", viaUplink, "P-6: the p2p part in observe or off refuses nothing"},
	{"P-2", viaUplink, "P-6: the p2p part in observe or off refuses nothing"},
	{"P-3", viaUplink, "P-6: the p2p part in observe or off refuses nothing"},
	{"P-4", viaUplink, "P-6: the p2p part in observe or off refuses nothing"},
}

type expectation struct {
	id   string
	want string
	why  string
}

var enforce = []expectation{
	{"F-1", viaExit, "I-1: a local TCP connection to an RU site goes through the exit"},
	{"F-3", viaExit, "I-1: local UDP to an RU site goes through the exit"},
	{"F-2", ruClient, "I-3: an RU client's TCP session to the node gets its replies"},
	{"F-4", ruClient, "I-3: an RU client's UDP to the node gets its replies"},
	{"F-5", viaUplink, "I-3: a server reaching an RU client from its listening port stays direct"},
	{"F-5x", viaExit, "I-1: the node opening a connection to an RU address from any other port uses the exit"},
	{"F-6", viaExit, "I-1: downstream TCP to an RU site goes through the exit"},
	{"F-6u", viaExit, "I-1: downstream UDP to an RU site goes through the exit"},
	{"F-7", viaUplink, "I-4: downstream TCP to a foreign site is untouched"},
	{"F-7u", viaUplink, "I-4: downstream UDP to a foreign site is untouched"},
	{"F-9", viaExit + " " + viaExit, "I-1: every packet of a connection follows its first one"},
	{"F-10", viaExit, "I-1: downstream QUIC to an RU site goes through the exit"},
	{"F-11", ruClient, "I-3: an RU client's QUIC to the node gets its replies"},
	{"F-12", viaUplink + " " + viaUplink, "a connection older than the rules keeps its path"},
	{"F-13", viaUplink, "known hole of the listen-port safety net (ТЗ §3.4)"},
	{"L-1", viaUplink, "I-4: a local connection to a foreign site is untouched"},
	{"V6-1", "err=ECONNREFUSED", "I-1: an RU destination over IPv6 is blocked at once — exits carry IPv4 only (ТЗ §3.5)"},
	{"V6-2", viaUplink6, "I-4: a foreign IPv6 destination is untouched"},
	{"D-3", viaUplink, "before anyone resolved it, an RU domain's foreign address is not in the policy"},
	{"D-1", viaExit, "I-1: an RU domain on a foreign address, resolved through the node, goes through the exit"},
	{"D-2", viaUplink, "I-4: a resolved foreign domain is untouched"},
	{"D-3b", viaExit, "the same address, once resolved as an RU domain, goes through the exit"},
	{"D-4", "err=timeout", "the resolver is closed on the uplink: no open resolver"},
	{"D-5", viaExit, "I-1: the host's own DNS is redirected too, and the resolver's upstream queries are not"},
	{"D-6", viaUplink, "with the resolver down, DNS is not redirected: the node keeps resolving on its own"},
	{"FC-1", "err=ECONNREFUSED", "I-2: exit declared dead — a local connection is refused at once"},
	{"FC-2", "err=ECONNREFUSED", "I-2: exit declared dead — a downstream connection is refused at once"},
	{"FC-3", viaUplink, "I-4: with the exit dead, foreign traffic is untouched"},
	{"FC-4", ruClient, "I-5: with the exit dead, the node stays reachable"},
	{"FC-8", viaExit, "the exit's probe (bypass bit + exit mark) reaches the exit even while it is declared dead"},
	{"FC-6", "err=ENETUNREACH", "I-2: no agent, interface gone — the unreachable rule fails transit"},
	{"FC-7", viaUplink, "I-4: with the exit gone, foreign traffic is untouched"},
}

var observe = []expectation{
	{"F-1", viaUplink, "observe changes no traffic"},
	{"F-6", viaUplink, "observe changes no traffic"},
	{"F-2", ruClient, "I-3 holds in observe"},
	{"F-4", ruClient, "I-3 holds in observe"},
	{"V6-1", viaUplink6, "observe changes no IPv6 traffic either"},
}

// egressOff is the destination policy lifted: RU goes out directly.
var egressOff = []expectation{
	{"F-1", viaUplink, "egress off: no destination is rerouted"},
	{"F-6", viaUplink, "egress off: no destination is rerouted"},
	{"F-2", ruClient, "I-3 holds with the egress off"},
}

func TestFlowModelEnforce(t *testing.T) {
	results := runStand(t, policy.ModeEnforce, policy.ModeEnforce, policy.ModeEnforce)
	check(t, results, enforce)
	check(t, results, guarded)
	check(t, results, p2pRefused)
	check(t, results, p2pPassed)
	requireCounted(t, results, "CNT-decide", "CNT-listen", "CNT-guard", "CNT-p2p")

	// I-2 without an agent: a local socket picked its route before the mark
	// rerouted it, so the kernel drops the packet silently and the client
	// times out. That is slow but must never be a way out.
	if got := results["FC-5"]; !strings.HasPrefix(got, "err=") {
		t.Errorf("FC-5 = %q, want an error — no agent, interface gone, the connection must not get out", got)
	}
}

func TestFlowModelObserve(t *testing.T) {
	results := runStand(t, policy.ModeObserve, policy.ModeObserve, policy.ModeObserve)
	check(t, results, observe)
	check(t, results, observed)
	check(t, results, p2pAllowed)
	check(t, results, p2pPassed)
	requireCounted(t, results, "CNT-decide", "CNT-listen", "CNT-guard", "CNT-p2p")
}

// G-7: the guard stands alone when the egress is off.
func TestFlowModelGuardOnly(t *testing.T) {
	results := runStand(t, policy.ModeOff, policy.ModeEnforce, policy.ModeOff)
	check(t, results, egressOff)
	check(t, results, guarded)
	check(t, results, p2pAllowed)
	requireCounted(t, results, "CNT-guard")
}

// P-6: the p2p part stands alone when the egress and the guard are off.
func TestFlowModelP2POnly(t *testing.T) {
	results := runStand(t, policy.ModeOff, policy.ModeOff, policy.ModeEnforce)
	check(t, results, egressOff)
	check(t, results, p2pRefused)
	check(t, results, p2pPassed)
	requireCounted(t, results, "CNT-p2p")
}

func check(t *testing.T, results map[string]string, want []expectation) {
	t.Helper()
	for _, e := range want {
		if got := results[e.id]; got != e.want {
			t.Errorf("%s = %q, want %q — %s", e.id, got, e.want, e.why)
		}
	}
}

func requireCounted(t *testing.T, results map[string]string, ids ...string) {
	t.Helper()
	for _, id := range ids {
		if n, err := strconv.Atoi(results[id]); err != nil || n == 0 {
			t.Errorf("%s = %q, want a positive count", id, results[id])
		}
	}
}

// runStand plans the state for the stand's node, renders it and runs
// stand.sh, returning its observations by scenario id.
func runStand(t *testing.T, egress, guard, p2p policy.Mode) map[string]string {
	t.Helper()
	if testing.Short() {
		t.Skip("the flow stand takes seconds; skipped in -short")
	}
	testsupport.RequireNetns(t)
	if _, err := exec.LookPath("dnsmasq"); err != nil {
		t.Skip("the stand's upstream DNS is a dnsmasq: it is not installed")
	}
	if _, err := exec.LookPath("setpriv"); err != nil {
		t.Skip("the stand drops the resolver to its own user with setpriv: it is not installed")
	}
	// Any user mapped into the stand's namespace will do.
	uid := uint32(testsupport.ResolverUID)
	if err := exec.Command("unshare", "-Ur", "--map-auto", "true").Run(); err != nil {
		t.Skipf("the stand maps the resolver's user into its namespace, which needs subuids: %v", err)
	}

	cfg := testsupport.Policy()
	cfg.Mode = egress
	cfg.Guard.Mode = guard
	cfg.P2P = policy.P2P{Mode: p2p, Signatures: policy.Signatures}
	cfg.Uplinks = []string{"up0"}
	in := testsupport.PlanInput()
	in.Policy = cfg
	in.Listen = netstate.Ports{TCP: []uint16{22}, UDP: []uint16{443, 8851}}
	in.Resolver = planner.ResolverStatus{UID: uid, Up: true}
	state := testsupport.MustPlan(t, in)

	// FLOWSTAND_DIR keeps the generated files, to run stand.sh by hand.
	dir := os.Getenv("FLOWSTAND_DIR")
	if dir == "" {
		dir = t.TempDir()
	} else if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, "vnm.nft"), nftables.Script(state))
	write(t, filepath.Join(dir, "routing.sh"), routingScript(state))
	conf, err := resolver.Config(state.DNS, state.Classify.Uplinks).Encode()
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, "resolver.json"), string(conf))
	build := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-o", filepath.Join(dir, "vnm"), "../../cmd/vnm")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build vnm: %v\n%s", err, out)
	}
	probe, err := os.ReadFile(filepath.Join("testdata", "probe.py"))
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, "probe.py"), string(probe))

	// The fail-closed scenarios need the egress in enforce.
	modeArg := egress.String()
	stand, err := filepath.Abs(filepath.Join("testdata", "stand.sh"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("unshare", "-Urnm", "--map-auto", "--pid", "--fork", "--propagation", "private", "bash", stand, dir, modeArg)
	cmd.Env = append(os.Environ(), fmt.Sprintf("RESOLVER_UID=%d", uid))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("stand failed: %v\n%s", err, out)
	}
	t.Logf("stand output:\n%s", out)
	return parse(string(out))
}

// routingScript writes the state's rules and routes as ip commands, through the
// same argument builders the agent uses, in the applier's order: every
// unreachable rule before any lookup rule (invariant I-2).
func routingScript(s netstate.State) string {
	var b strings.Builder
	rules := slices.Clone(s.Rules)
	slices.SortStableFunc(rules, func(a, b netstate.IPRule) int {
		return cmp.Compare(lookupLast(a), lookupLast(b))
	})
	for _, r := range rules {
		b.WriteString("ip rule add " + strings.Join(iproute.RuleArgs(r), " ") + "\n")
	}
	for _, r := range s.Routes {
		b.WriteString("ip route replace " + strings.Join(iproute.RouteArgs(r), " ") + "\n")
	}
	return b.String()
}

func parse(out string) map[string]string {
	results := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		id, result, ok := strings.Cut(sc.Text(), " ")
		if ok {
			results[id] = result
		}
	}
	return results
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func lookupLast(r netstate.IPRule) int {
	if r.Action == netstate.RuleLookup {
		return 1
	}
	return 0
}
