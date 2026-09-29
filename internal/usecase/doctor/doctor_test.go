package doctor_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lib4u/vnm/internal/domain/netstate"
	"github.com/lib4u/vnm/internal/domain/policy"
	"github.com/lib4u/vnm/internal/testsupport"
	"github.com/lib4u/vnm/internal/usecase/agent"
	"github.com/lib4u/vnm/internal/usecase/doctor"
	"github.com/lib4u/vnm/internal/usecase/exits"
)

var now = time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)

type node struct {
	cfgErr    error
	snap      agent.Snapshot
	snapErr   error
	inactive  map[string]bool
	verifyErr error
	forward   string
	nftConf   string
	firewall  string
	portShut  bool
	fwdShut   bool
}

func (n *node) Load() (policy.Config, string, error) {
	return testsupport.Policy(), "v1", n.cfgErr
}
func (n *node) Read() (agent.Snapshot, error)                 { return n.snap, n.snapErr }
func (n *node) Active(_ context.Context, unit string) bool    { return !n.inactive[unit] }
func (n *node) Enabled(_ context.Context, unit string) bool   { return !n.inactive[unit] }
func (n *node) Verify(context.Context, netstate.State) error  { return n.verifyErr }
func (n *node) LastGood() (netstate.State, bool, error)       { return netstate.State{}, true, nil }
func (n *node) ForwardPolicy(context.Context) (string, error) { return n.forward, nil }
func (n *node) ForwardAllowedTo(context.Context, string) (string, bool, error) {
	return n.firewall, !n.fwdShut, nil
}
func (n *node) PortAllowed(context.Context, uint16) (string, bool, error) {
	return n.firewall, !n.portShut, nil
}

// files serves /etc/nftables.conf.
type files struct{ n *node }

func (f files) Read(string) ([]byte, error) { return []byte(f.n.nftConf), nil }

func healthy() *node {
	return &node{
		forward:  "ACCEPT",
		firewall: "ufw",
		inactive: map[string]bool{},
		snap: agent.Snapshot{
			ConfigValid:   true,
			PolicyApplied: true,
			ListsCurrent:  true,
			Mode:          policy.ModeEnforce,
			Exits:         []exits.Status{{Name: "warp", Present: true, Healthy: true}},
			Resolver:      agent.ResolverSnapshot{Enabled: true, Up: true},
			Lists: map[string]agent.ListStatus{
				"ru_ip":    {Entries: 25113, Refresh: 24 * time.Hour, Age: 5 * time.Hour},
				"scanners": {Entries: 3},
				// Downloaded for a guard not in the policy: never a finding.
				"unused": {Missing: true, Refresh: 24 * time.Hour},
			},
			Guard:         agent.GuardSnapshot{Mode: policy.ModeEnforce, Refused: map[string]uint64{"scanners": 4}},
			LastReconcile: now.Add(-10 * time.Second),
		},
	}
}

func run(n *node) []doctor.Finding {
	return doctor.New(doctor.Deps{
		Config: n, Status: n, Units: n, Kernel: n, Store: n, Forward: n, Firewall: n, Files: files{n},
		Now: func() time.Time { return now },
	}).Run(context.Background())
}

func level(findings []doctor.Finding, check string) doctor.Level {
	for _, f := range findings {
		if f.Check == check {
			return f.Level
		}
	}
	return 0
}

func TestHealthyNode(t *testing.T) {
	findings := run(healthy())
	for _, f := range findings {
		if f.Level != doctor.LevelOK {
			t.Errorf("%s: %s %s", f.Check, f.Level, f.Detail)
		}
	}
	if doctor.Failed(findings) {
		t.Fatal("a healthy node failed")
	}
}

func TestFindings(t *testing.T) {
	tests := []struct {
		name    string
		breakIt func(n *node)
		check   string
		want    doctor.Level
	}{
		{"invalid config", func(n *node) { n.cfgErr = errors.New("bad yaml") }, "config", doctor.LevelFail},
		{"agent stopped", func(n *node) { n.inactive["vnm-agent.service"] = true }, "agent unit", doctor.LevelFail},
		{"boot unit disabled", func(n *node) { n.inactive["vnm-boot.service"] = true }, "boot unit", doctor.LevelFail},
		{"resolver unit stopped", func(n *node) { n.inactive["vnm-dns.service"] = true }, "resolver unit", doctor.LevelFail},
		{"kernel drifted", func(n *node) { n.verifyErr = errors.New("table gone") }, "kernel", doctor.LevelFail},
		{"forward drop", func(n *node) { n.forward = "DROP" }, "forward", doctor.LevelWarn},
		// ufw dropping the resolver's port leaves tunnel clients without DNS.
		{"resolver port shut", func(n *node) { n.portShut = true }, "resolver port", doctor.LevelFail},
		// firewalld not forwarding to the exit makes its destinations unreachable.
		{"exit forwarding shut", func(n *node) { n.fwdShut = true }, "exit warp forwarding", doctor.LevelFail},
		{"agent stuck", func(n *node) { n.snap.LastReconcile = now.Add(-5 * time.Minute) }, "agent", doctor.LevelFail},
		{"no snapshot", func(n *node) { n.snapErr = errors.New("no file") }, "agent", doctor.LevelFail},
		{"observe", func(n *node) { n.snap.Mode = policy.ModeObserve }, "mode", doctor.LevelWarn},
		{"exit dead", func(n *node) { n.snap.Exits[0].Healthy = false }, "exit warp", doctor.LevelFail},
		{"resolver down", func(n *node) { n.snap.Resolver.Up = false }, "resolver", doctor.LevelWarn},
		{"list 4 refreshes old", func(n *node) { setList(n, "ru_ip", func(l *agent.ListStatus) { l.Age = 4 * 24 * time.Hour }) }, "list ru_ip", doctor.LevelWarn},
		{"list 8 refreshes old", func(n *node) { setList(n, "ru_ip", func(l *agent.ListStatus) { l.Age = 8 * 24 * time.Hour }) }, "list ru_ip", doctor.LevelFail},
		{"list missing", func(n *node) { setList(n, "ru_ip", func(l *agent.ListStatus) { l.Missing = true }) }, "list ru_ip", doctor.LevelFail},
		{"guard list never resolved", func(n *node) {
			setList(n, "scanners", func(l *agent.ListStatus) { l.Failed, l.Entries = true, 0 })
		}, "list scanners", doctor.LevelFail},
		{"guard list update failed", func(n *node) { setList(n, "scanners", func(l *agent.ListStatus) { l.Failed = true }) }, "list scanners", doctor.LevelWarn},
		{"guard observe", func(n *node) { n.snap.Guard.Mode = policy.ModeObserve }, "guard", doctor.LevelWarn},
		{"policy not applied", func(n *node) { n.snap.PolicyApplied = false }, "policy", doctor.LevelFail},
		{"lists behind the copies", func(n *node) { n.snap.ListsCurrent = false }, "policy", doctor.LevelWarn},
		{"nftables flushes everything", func(n *node) { n.nftConf = "#!/usr/sbin/nft -f\nflush ruleset\n" }, "nftables", doctor.LevelWarn},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := healthy()
			tt.breakIt(n)
			if got := level(run(n), tt.check); got != tt.want {
				t.Fatalf("%s = %s, want %s", tt.check, got, tt.want)
			}
		})
	}
}

func setList(n *node, name string, change func(*agent.ListStatus)) {
	l := n.snap.Lists[name]
	change(&l)
	n.snap.Lists[name] = l
}
