// Package e2e runs the built vnm binary against a real kernel in a throwaway
// network namespace: config in, kernel state and metrics out.
//
// The namespace has no internet, which the test uses: the exit's probe cannot
// pass, so the agent must bring the exit up, find it dead and fail closed.
package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/lib4u/vnm/internal/testsupport"
)

func TestMain(m *testing.M) {
	os.Exit(testsupport.MainInNetns(m))
}

type node struct {
	t      *testing.T
	bin    string
	dir    string
	config string
}

func newNode(t *testing.T) *node {
	t.Helper()
	testsupport.RequireInNetns(t)
	if testing.Short() {
		t.Skip("builds and runs the binary")
	}
	dir := t.TempDir()
	n := &node{t: t, bin: filepath.Join(dir, "vnm"), dir: dir, config: filepath.Join(dir, "config.yaml")}

	build := exec.Command("go", "build", "-o", n.bin, "../../cmd/vnm")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	n.sh("ip link set lo up && ip link add up0 type dummy && ip link set up0 up && " +
		"ip addr add 192.0.2.100/24 dev up0 && ip route add default via 192.0.2.254 dev up0")

	priv, _ := wgtypes.GeneratePrivateKey()
	peer, _ := wgtypes.GeneratePrivateKey()
	n.write("warp.conf", "[Interface]\nPrivateKey = "+priv.String()+"\nAddress = 172.16.0.2/32\nMTU = 1280\n"+
		"[Peer]\nPublicKey = "+peer.PublicKey().String()+"\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n")
	n.write("ru.txt", "198.51.100.0/24\n2001:db8:100::/48\n")
	n.write("config.yaml", `
version: 1
mode: enforce
exits:
  - name: warp
    slot: 0
    iface: warp
    conf: `+filepath.Join(dir, "warp.conf")+`
    endpoints: ["192.0.2.1:2408"]
    health: { url: "https://127.0.0.1:1/cdn-cgi/trace", expect: "warp=on" }
lists:
  - name: ru_ip
    ip: ["file:`+filepath.Join(dir, "ru.txt")+`"]
policy:
  - lists: [ru_ip]
    action: exit:warp
    fallback: block
`)
	return n
}

func (n *node) sh(script string) string {
	n.t.Helper()
	out, err := testsupport.Shell(script)
	if err != nil {
		n.t.Fatalf("%s: %v\n%s", script, err, out)
	}
	return out
}

func (n *node) write(name, content string) {
	n.t.Helper()
	if err := os.WriteFile(filepath.Join(n.dir, name), []byte(content), 0o600); err != nil {
		n.t.Fatal(err)
	}
}

func (n *node) vnm(args ...string) *exec.Cmd {
	flags := []string{
		"-config", n.config,
		"-state-dir", filepath.Join(n.dir, "state"),
		"-lock", filepath.Join(n.dir, "run", "state.lock"),
		"-metrics", filepath.Join(n.dir, "vnm.prom"),
	}
	return exec.Command(n.bin, append(args, flags...)...)
}

// waitFor polls cond until it holds or the deadline passes.
func waitFor(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestAgentFailsClosedThenBootRestores(t *testing.T) {
	n := newNode(t)

	agent := n.vnm("agent")
	var logs strings.Builder
	agent.Stdout, agent.Stderr = &logs, &logs
	if err := agent.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if agent.ProcessState == nil {
			_ = agent.Process.Signal(syscall.SIGTERM)
			_ = agent.Wait()
		}
		t.Logf("agent log:\n%s", logs.String())
	}()

	waitFor(t, "the policy to be applied", 10*time.Second, func() bool {
		out, err := testsupport.Shell("nft list table inet vnm")
		return err == nil && strings.Contains(out, "198.51.100.0/24")
	})
	rules := n.sh("ip rule show")
	if !strings.Contains(rules, "1000:") || !strings.Contains(rules, "1001:") || !strings.Contains(rules, "unreachable") {
		t.Fatalf("exit rules missing:\n%s", rules)
	}
	// The exit was created from its config — the agent is its only controller.
	if out := n.sh("ip -d link show warp"); !strings.Contains(out, "wireguard") {
		t.Fatalf("exit interface:\n%s", out)
	}
	// Nothing answers the probe here, so the exit is dead and its connections
	// are refused (I-2).
	if out := n.sh("nft list set inet vnm dead_exits"); !strings.Contains(out, "0x0000ca6c") {
		t.Fatalf("exit not declared dead:\n%s", out)
	}
	metrics, err := os.ReadFile(filepath.Join(n.dir, "vnm.prom"))
	if err != nil || !strings.Contains(string(metrics), `vnm_exit_healthy{exit="warp"} 0`) {
		t.Fatalf("metrics: %v\n%s", err, metrics)
	}

	if err := agent.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := agent.Wait(); err != nil {
		t.Fatalf("agent exit: %v", err)
	}

	// A reboot: the kernel state is gone and so is the exit's interface. The
	// boot unit restores the policy from disk before anything else runs.
	n.sh("nft flush ruleset && ip rule del priority 1000 && ip rule del priority 1001 && ip link del warp")
	if out, err := n.vnm("boot").CombinedOutput(); err != nil {
		t.Fatalf("boot: %v\n%s", err, out)
	}
	if out := n.sh("nft list table inet vnm"); !strings.Contains(out, "198.51.100.0/24") {
		t.Fatal("boot did not restore the table")
	}
	if rules := n.sh("ip rule show"); !strings.Contains(rules, "unreachable") {
		t.Fatalf("boot did not restore the rules:\n%s", rules)
	}
}
