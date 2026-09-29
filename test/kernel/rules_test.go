package kernel

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lib4u/vnm/internal/infrastructure/iproute"
	"github.com/lib4u/vnm/internal/infrastructure/runner"
	"github.com/lib4u/vnm/internal/usecase/apply"
)

// A foreign rule without a mark at an owned priority is removed and the
// agent's rule of that priority stays: a deletion that left the mark out of
// the rule, or sent a zero one, would match whichever rule comes first there.
func TestForeignRuleWithoutMarkIsRemovedExactly(t *testing.T) {
	r := newRig(t)
	want := desired(t)
	if err := r.applier.Apply(context.Background(), want); err != nil {
		t.Fatal(err)
	}
	r.sh(t, "ip rule add priority 1001 iif lo nop && ip rule add priority 1000 from 10.9.0.0/16 goto 1005")

	if err := r.applier.Apply(context.Background(), want); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	r.requireApplied(t, want)
}

// Every kind of selector ip prints makes it back into the deletion: foreign
// rules of all kinds next to the agent's are removed, and only them.
func TestForeignRulesOfEveryKindAreRemovedExactly(t *testing.T) {
	r := newRig(t)
	want := desired(t)
	if err := r.applier.Apply(context.Background(), want); err != nil {
		t.Fatal(err)
	}
	for _, rule := range []string{
		"priority 1000 fwmark 0xca6c/0xffff iif eth9 lookup 51820",
		"priority 1001 fwmark 0xca6c/0xffff oif lo unreachable",
		"priority 1001 not from 10.0.0.0/8 to 192.0.2.1 tos 0x10 uidrange 0-0 ipproto tcp sport 80 " +
			"dport 1000-2000 lookup main suppress_prefixlength 0 protocol static",
		"priority 1000 fwmark 0/0xff goto 1100",
		"priority 1001 fwmark 0x0/0xffffffff realms 3/4 lookup 100 suppress_ifgroup 5",
		"priority 1000 dscp 8/0x38 dport 53/0xff l3mdev",
		"priority 1001 fwmark 0xca6c blackhole",
	} {
		r.sh(t, "ip rule add "+rule)
	}

	if err := r.applier.Apply(context.Background(), want); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	r.requireApplied(t, want)
}

// A foreign rule that carries the agent's mark and action but matches on more
// than the mark is not the agent's rule: it catches only part of the marked
// traffic. It is removed, and the agent's own rule goes in.
func TestForeignRuleWithExtraSelectorIsNotOurs(t *testing.T) {
	r := newRig(t)
	want := desired(t)
	r.sh(t, "ip rule add priority 1000 fwmark 0xca6c/0xffff iif lo lookup 51820")

	if err := r.applier.Apply(context.Background(), want); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	r.requireApplied(t, want)
	if got := r.sh(t, "ip rule show priority 1000"); strings.Contains(got, "iif") {
		t.Fatalf("the foreign rule stayed:\n%s", got)
	}
}

// Routes without a device — unreachable, blackhole — a second default with a
// metric, one with a TOS and one through a gateway, left in an owned table,
// are removed exactly; the agent's own route stays.
func TestForeignRoutesInOwnedTableAreRemoved(t *testing.T) {
	r := newRig(t)
	want := desired(t)
	if err := r.applier.Apply(context.Background(), want); err != nil {
		t.Fatal(err)
	}
	r.sh(t, "ip link add up1 type dummy && ip link set up1 up && ip addr add 198.51.100.2/24 dev up1")
	defer r.sh(t, "ip link del up1")
	r.sh(t, "ip route add unreachable default table 51820 metric 10 && "+
		"ip route add default dev up1 table 51820 metric 20 && "+
		"ip route add default tos 0x10 dev warp table 51820 && "+
		"ip route add blackhole default table 51821 && "+
		"ip route add default via 198.51.100.1 table 51823 metric 3 && "+
		"ip route add prohibit default table 51822 metric 5")

	if err := r.applier.Apply(context.Background(), want); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	r.requireApplied(t, want)
}

// A node whose default route is multipath — or a nexthop group — has uplinks
// only inside its nexthops.
func TestMultipathUplinks(t *testing.T) {
	r := newRig(t)
	r.sh(t, "ip link add up0 type dummy && ip link set up0 up && ip addr add 192.0.2.100/24 dev up0 && "+
		"ip link add up1 type dummy && ip link set up1 up && ip addr add 198.51.100.100/24 dev up1")
	defer r.sh(t, "ip link del up0 && ip link del up1")

	for _, route := range []string{
		"ip route add default nexthop via 192.0.2.254 dev up0 nexthop via 198.51.100.254 dev up1",
		"ip nexthop add id 1 via 192.0.2.254 dev up0 && ip nexthop add id 2 via 198.51.100.254 dev up1 && " +
			"ip nexthop add id 10 group 1/2 && ip route add default nhid 10",
	} {
		r.sh(t, route)
		uplinks, err := r.rt.Uplinks(context.Background())
		if err != nil || !slices.Equal(uplinks, []string{"up0", "up1"}) {
			t.Errorf("%s: Uplinks = %v, %v", route, uplinks, err)
		}
		r.sh(t, "ip route del default && ip nexthop flush")
	}
}

// A default through a gateway in place of the agent's route is not the
// agent's route, though it leaves by the same device: Verify notices, and the
// next apply puts the agent's back.
func TestRouteThroughGatewayIsNotOurs(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	want := desired(t)
	if err := r.applier.Apply(ctx, want); err != nil {
		t.Fatal(err)
	}
	r.sh(t, "ip route replace default via 192.0.2.1 dev warp onlink table 51820")
	if err := r.applier.Verify(ctx, want); !errors.Is(err, apply.ErrDiverged) {
		t.Fatalf("Verify: want ErrDiverged, got %v", err)
	}
	if err := r.applier.Apply(ctx, want); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	r.requireApplied(t, want)
}

// A foreign rule the kernel takes for the agent's — it differs only in an
// inverted match or in its protocol — refuses the agent's rule for as long as
// it is there. It goes, and the agent's rule goes in.
func TestForeignTwinOfOurRuleIsReplaced(t *testing.T) {
	r := newRig(t)
	want := desired(t)
	r.sh(t, "ip rule add priority 1001 not fwmark 0xca6c/0xffff unreachable && "+
		"ip rule add priority 1000 fwmark 0xca6c/0xffff lookup 51820 protocol static")

	if err := r.applier.Apply(context.Background(), want); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	r.requireApplied(t, want)
	if got := r.sh(t, "ip rule show"); strings.Contains(got, "not ") || strings.Contains(got, "proto static") {
		t.Fatalf("a twin stayed:\n%s", got)
	}
}

// confRunner runs ip in a mount namespace of its own with dir mounted over
// /etc/iproute2: ip prints the table names dir defines, and the host's
// configuration stays as it is.
type confRunner struct {
	runner.System
	dir string
}

func (c confRunner) Run(ctx context.Context, cmd runner.Command) (string, error) {
	if cmd.Name == "ip" {
		script := `mount --bind "$0" /etc/iproute2 && exec ip "$@"`
		cmd.Name, cmd.Args = "unshare", append([]string{"-m", "sh", "-c", script, c.dir}, cmd.Args...)
	}
	return c.System.Run(ctx, cmd)
}

// A node that names the agent's tables — ip then prints "lookup warp" — still
// has its rules and routes recognised, and foreign routes in them removed.
func TestNamedOwnedTables(t *testing.T) {
	r := newRig(t)
	if _, err := os.Stat("/etc/iproute2"); err != nil {
		t.Skip("no /etc/iproute2 to mount a configuration over")
	}
	ctx := context.Background()
	root := t.TempDir()
	dir := filepath.Join(root, "etc", "iproute2")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "rt_tables"), []byte("51820 warp\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run := confRunner{System: runner.System{Timeout: 10 * time.Second}, dir: dir}
	rt := iproute.NewRouter(run, iproute.WithConfigRoot(os.DirFS(root)))
	applier := apply.New(r.fw, rt, r.store)

	want := desired(t)
	r.sh(t, "ip route add unreachable default table 51820 metric 10")
	if err := applier.Apply(ctx, want); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if out, err := run.Run(ctx, runner.Command{Name: "ip", Args: []string{"rule", "show", "priority", "1000"}}); err != nil || !strings.Contains(out, "lookup warp") {
		t.Fatalf("ip does not print the table name, the test proves nothing: %v\n%s", err, out)
	}
	rules, err := rt.Rules(ctx)
	if err != nil || !slices.Equal(rules, want.Rules) {
		t.Errorf("rules = %+v, %v; want %+v", rules, err, want.Rules)
	}
	routes, err := rt.Routes(ctx)
	if err != nil || !slices.Equal(routes, want.Routes) {
		t.Errorf("routes = %+v, %v; want %+v", routes, err, want.Routes)
	}
}
