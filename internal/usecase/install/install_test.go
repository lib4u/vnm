package install_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	vnm "github.com/lib4u/vnm"
	"github.com/lib4u/vnm/internal/domain/netstate"
	"github.com/lib4u/vnm/internal/usecase/install"
)

// host fakes every port and records what happened, in order. An action whose
// log entry is in fail fails instead.
type host struct {
	files   map[string][]byte
	modes   map[string]os.FileMode
	log     []string
	fail    map[string]error
	osID    string
	osVer   string
	arch    string
	ram     int
	swap    int
	swapOn  map[string]bool
	sysctl  map[string]string
	session string
	// sshUnit and firewall model the distribution.
	firewall  string
	sshUnit   string
	active    map[string]bool
	enabled   map[string]bool
	scheduled map[string]bool
	rules     []netstate.IPRule
	registed  bool
	license   string
}

func newHost() *host {
	return &host{
		files: map[string][]byte{"/root/.ssh/authorized_keys": []byte("ssh-ed25519 AAAA op@host\n"), "/proc/self/exe": []byte("ELF")},
		modes: map[string]os.FileMode{}, fail: map[string]error{},
		osID: "ubuntu", osVer: "24.04", arch: "amd64", ram: 4096, swap: 0,
		swapOn: map[string]bool{}, sysctl: map[string]string{}, session: "203.0.113.7 50022 198.51.100.1 22",
		active: map[string]bool{}, enabled: map[string]bool{}, scheduled: map[string]bool{},
	}
}

func (h *host) do(s string) error {
	h.log = append(h.log, s)
	return h.fail[s]
}

func (h *host) Write(path string, data []byte, mode os.FileMode) (bool, error) {
	if old, ok := h.files[path]; ok && bytes.Equal(old, data) && h.modes[path] == mode {
		return false, nil
	}
	h.files[path], h.modes[path] = data, mode
	return true, h.do("write " + path)
}

func (h *host) Read(path string) ([]byte, error) {
	data, ok := h.files[path]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return data, nil
}

func (h *host) Exists(path string) bool { _, ok := h.files[path]; return ok }

func (h *host) Remove(path string) error {
	if _, ok := h.files[path]; ok {
		delete(h.files, path)
		return h.do("remove " + path)
	}
	return nil
}

func (h *host) Install(_ context.Context, names ...string) error {
	return h.do("apt " + strings.Join(names, " "))
}

func (h *host) DaemonReload(context.Context) error { return h.do("daemon-reload") }
func (h *host) EnableNow(_ context.Context, units ...string) error {
	if err := h.do("enable " + strings.Join(units, " ")); err != nil {
		return err
	}
	for _, u := range units {
		h.enabled[u], h.active[u] = true, true
	}
	return nil
}
func (h *host) Restart(_ context.Context, u string) error { return h.do("restart " + u) }
func (h *host) Reload(_ context.Context, u string) error  { return h.do("reload " + u) }
func (h *host) DisableNow(_ context.Context, u string) error {
	return h.do("disable " + u)
}
func (h *host) Enabled(_ context.Context, u string) bool { return h.enabled[u] }
func (h *host) Active(_ context.Context, u string) bool  { return h.active[u] }
func (h *host) Schedule(_ context.Context, name string, after time.Duration, _ ...string) error {
	if err := h.do("schedule " + name + " " + after.String()); err != nil {
		return err
	}
	h.scheduled[name] = true
	return nil
}
func (h *host) Scheduled(_ context.Context, name string) bool { return h.scheduled[name] }
func (h *host) Cancel(_ context.Context, name string) error {
	if !h.scheduled[name] {
		return nil
	}
	delete(h.scheduled, name)
	return h.do("cancel " + name)
}

func (h *host) OSRelease() (string, string, error) { return h.osID, h.osVer, nil }
func (h *host) Arch() string                       { return h.arch }
func (h *host) MemoryMB() (int, int, error)        { return h.ram, h.swap, nil }
func (h *host) Sysctl(key string) (string, error) {
	v, ok := h.sysctl[key]
	if !ok {
		return "", fs.ErrNotExist
	}
	return v, nil
}

// ReloadSysctl makes every value of the tuning live.
func (h *host) ReloadSysctl(context.Context) error {
	if err := h.do("sysctl"); err != nil {
		return err
	}
	for line := range strings.Lines(string(install.Sysctl())) {
		if k, v, ok := strings.Cut(line, "="); ok && !strings.HasPrefix(line, "#") {
			h.sysctl[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return nil
}
func (h *host) CheckSSHD(context.Context) error      { return nil }
func (h *host) SwapActive(path string) (bool, error) { return h.swapOn[path], nil }
func (h *host) AddSwap(_ context.Context, path string, _ int) error {
	h.files[path] = nil
	if err := h.do("swap " + path); err != nil {
		return err
	}
	h.swapOn[path] = true
	return nil
}
func (h *host) SSHConnection() string { return h.session }
func (h *host) SSHUnit() string {
	if h.sshUnit == "" {
		return "ssh"
	}
	return h.sshUnit
}
func (h *host) AllowPort(_ context.Context, port uint16, _ string) (string, error) {
	return h.firewall, h.do(fmt.Sprintf("allow %d", port))
}
func (h *host) AllowForwardTo(_ context.Context, iface string) (string, error) {
	return h.firewall, h.do("forward " + iface)
}
func (h *host) EnsureSystemUser(_ context.Context, name string) error {
	return h.do("user " + name)
}
func (h *host) Executable() (string, error) { return "/proc/self/exe", nil }

func (h *host) EnsureTool(context.Context) error { return h.do("wgcf tool") }
func (h *host) Registered() bool                 { return h.registed }
func (h *host) Register(context.Context) error {
	h.registed = true
	return h.do("wgcf register")
}
func (h *host) ApplyLicense(_ context.Context, key string) (bool, error) {
	if err := h.do("wgcf license"); err != nil {
		return false, err
	}
	return true, nil
}
func (h *host) WriteExitConf(context.Context) error { return h.do("exit conf") }
func (h *host) License() (string, error)            { return h.license, nil }
func (h *host) Retire(context.Context) (func() error, error) {
	if err := h.do("wgcf retire"); err != nil {
		return nil, err
	}
	h.registed = false
	return func() error {
		h.registed = true
		return h.do("wgcf restore")
	}, nil
}

func (h *host) Rules(context.Context) ([]netstate.IPRule, error) { return slices.Clone(h.rules), nil }
func (h *host) AddRule(_ context.Context, r netstate.IPRule) error {
	h.rules = append(h.rules, r)
	return h.do("rule add " + ruleName(r))
}
func (h *host) DeleteRule(_ context.Context, r netstate.IPRule) error {
	h.rules = slices.DeleteFunc(h.rules, func(x netstate.IPRule) bool { return x == r })
	return h.do("rule del " + ruleName(r))
}

func ruleName(r netstate.IPRule) string {
	mask := ""
	if r.Mask != 0 {
		mask = "/mask"
	}
	return strings.TrimSpace(strconv.Itoa(r.Priority) + " " + mask)
}

var layout = install.Layout{
	Binary:     "/usr/local/bin/vnm",
	UnitDir:    "/etc/systemd/system",
	Config:     "/etc/vnm/config.yaml",
	StateDir:   "/var/lib/vnm",
	ConfigMode: 0o644,
}

func newInstaller(h *host) *install.Installer {
	return install.New(install.Deps{Files: h, Packages: h, Services: h, Host: h, Warp: h, Rules: h})
}

func TestPreflight(t *testing.T) {
	for _, tt := range []struct {
		id, version, arch string
		ok                bool
	}{
		{"ubuntu", "24.04", "amd64", true},
		{"almalinux", "9.7", "amd64", true}, // matched by the major version
		{"almalinux", "10.1", "amd64", true},
		{"almalinux", "8.10", "amd64", false},
		{"debian", "12", "amd64", false},
		// The pinned wgcf is an x86_64 build.
		{"ubuntu", "24.04", "arm64", false},
	} {
		h := newHost()
		h.osID, h.osVer, h.arch = tt.id, tt.version, tt.arch
		err := newInstaller(h).Preflight()
		if tt.ok && err != nil || !tt.ok && !errors.Is(err, install.ErrUnsupportedOS) {
			t.Errorf("%s %s %s: %v", tt.id, tt.version, tt.arch, err)
		}
	}
}

func TestPlaceFilesKeepsOperatorConfig(t *testing.T) {
	h := newHost()
	h.files["/etc/vnm/config.yaml"] = []byte("operator's own")
	changed, err := newInstaller(h).PlaceFiles(context.Background(), layout,
		install.Assets{Config: []byte("template"), BootUnit: []byte("boot"), AgentUnit: []byte("agent")})
	if err != nil {
		t.Fatal(err)
	}
	if string(h.files["/etc/vnm/config.yaml"]) != "operator's own" {
		t.Fatal("the operator's config was overwritten")
	}
	if !slices.Contains(changed, "/usr/local/bin/vnm") || !slices.Contains(h.log, "daemon-reload") {
		t.Fatalf("changed %v, log %v", changed, h.log)
	}
}

// The units take every path from the layout: the shipped units hold no path
// of their own.
func TestPlaceFilesRendersUnitsFromLayout(t *testing.T) {
	l := install.Layout{
		Binary: "/opt/vnm/bin/vnm", UnitDir: "/etc/systemd/system", Config: "/opt/vnm/etc/vnm.yaml",
		StateDir: "/opt/vnm/state", ConfigMode: 0o644,
	}
	h := newHost()
	_, err := newInstaller(h).PlaceFiles(context.Background(), l, install.Assets{
		Config: vnm.DefaultConfig, BootUnit: vnm.BootUnit, AgentUnit: vnm.AgentUnit, DNSUnit: vnm.DNSUnit,
	})
	if err != nil {
		t.Fatal(err)
	}
	for unit, want := range map[string][]string{
		install.BootUnit:  {"ExecStart=/opt/vnm/bin/vnm boot -config /opt/vnm/etc/vnm.yaml -state-dir /opt/vnm/state"},
		install.AgentUnit: {"ExecStart=/opt/vnm/bin/vnm agent -config /opt/vnm/etc/vnm.yaml -state-dir /opt/vnm/state"},
		install.DNSUnit: {
			"ConditionPathExists=/opt/vnm/state/dns/resolver.json",
			"StandardInput=file:/opt/vnm/state/dns/resolver.json",
			"ExecStart=/opt/vnm/bin/vnm dns serve -config -",
			"User=vnm-dns",
		},
	} {
		got := string(h.files[l.UnitDir+"/"+unit])
		for _, w := range want {
			if !strings.Contains(got, w) {
				t.Errorf("%s lacks %q:\n%s", unit, w, got)
			}
		}
		for _, stale := range []string{"{{", "/usr/local/bin/vnm", "/var/lib/vnm"} {
			if strings.Contains(got, stale) {
				t.Errorf("%s holds %q:\n%s", unit, stale, got)
			}
		}
	}
	// The mode switch rewrites the policy with the same mode.
	if h.modes[l.Config] != l.ConfigMode {
		t.Fatalf("config mode %v, want %v", h.modes[l.Config], l.ConfigMode)
	}
}

func TestPlaceFilesNeedsConfigMode(t *testing.T) {
	l := layout
	l.ConfigMode = 0
	if _, err := newInstaller(newHost()).PlaceFiles(context.Background(), l, install.Assets{}); err == nil {
		t.Fatal("a config without a mode would be written unreadable")
	}
}

func legacyNode() *host {
	h := newHost()
	h.rules = []netstate.IPRule{
		{Priority: 1000, Mark: 0xca6c, Action: netstate.RuleLookup, Table: 51820},
		{Priority: 1001, Mark: 0xca6c}, // blackhole: an action the domain does not express
	}
	h.files["/etc/cron.d/wtm-warp-watchdog"] = []byte("*/5 * * * * root /opt/wtm/warp-watchdog.sh")
	h.files["/etc/wireguard/warp.conf"] = []byte("[Interface]\nPostUp = ip rule add ...")
	h.enabled["wg-quick@warp.service"] = true
	// A hand-made WARP setup's boot unit that re-adds the blackhole at 1001.
	h.files["/etc/systemd/system/warp-failclosed.service"] = []byte("[Service]\nExecStart=/bin/sh -c 'ip rule add fwmark 51820 blackhole priority 1001'")
	h.enabled["warp-failclosed.service"] = true
	return h
}

func TestMigrateFailClosedOrder(t *testing.T) {
	h := legacyNode()
	migrated, err := newInstaller(h).Migrate(context.Background(), "/var/lib/vnm")
	if err != nil || !migrated {
		t.Fatalf("Migrate = %t, %v", migrated, err)
	}
	pos := func(s string) int {
		i := slices.Index(h.log, s)
		if i < 0 {
			t.Fatalf("%q missing from %v", s, h.log)
		}
		return i
	}
	// Our unreachable rule, then our lookup, then the old rules go.
	if !(pos("rule add 1001 /mask") < pos("rule add 1000 /mask") && pos("rule add 1000 /mask") < pos("rule del 1000")) {
		t.Fatalf("rule order: %v", h.log)
	}
	// wtm's watchdog goes before the interface, or it brings it back.
	if pos("remove /etc/cron.d/wtm-warp-watchdog") > pos("disable wg-quick@warp.service") {
		t.Fatalf("watchdog removed after the interface: %v", h.log)
	}
	if h.Exists("/etc/wireguard/warp.conf") {
		t.Fatal("old config left")
	}
	// The fail-closed unit would put its blackhole back beside our rules at
	// the next boot.
	if pos("disable warp-failclosed.service") < 0 || h.Exists("/etc/systemd/system/warp-failclosed.service") {
		t.Fatalf("warp-failclosed left: %v", h.log)
	}
	backedUp := false
	for path := range h.files {
		if strings.HasPrefix(path, "/var/lib/vnm/migration/") && strings.HasSuffix(path, "etc_wireguard_warp.conf") {
			backedUp = true
		}
	}
	if !backedUp {
		t.Fatalf("old config not backed up: %v", h.log)
	}
}

// Rules nobody can account for stop the migration before anything changes.
func TestMigrateStopsOnUnknownRules(t *testing.T) {
	h := legacyNode()
	h.rules = append(h.rules, netstate.IPRule{Priority: 1003, Mark: 0xca6d, Action: netstate.RuleLookup, Table: 51821})
	h.log = nil
	if _, err := newInstaller(h).Migrate(context.Background(), "/var/lib/vnm"); !errors.Is(err, install.ErrUnknownRules) {
		t.Fatalf("want ErrUnknownRules, got %v", err)
	}
	if len(h.log) != 0 {
		t.Fatalf("changes before stopping: %v", h.log)
	}
}

// A rule with the old mark that also matches on something else is not what a
// hand-made WARP puts there: nobody can account for it.
func TestPlanMigrationLegacyMarkWithSelectorIsUnknown(t *testing.T) {
	odd := netstate.IPRule{Priority: 1000, Mark: 0xca6c, Action: netstate.RuleLookup, Table: 51820, Extra: "iif eth0"}
	p := install.PlanMigration([]netstate.IPRule{odd})
	if len(p.Legacy) != 0 || !slices.Equal(p.Unknown, []netstate.IPRule{odd}) {
		t.Fatalf("plan = %+v, want the rule unknown", p)
	}
}

func TestMigrateNothingToDo(t *testing.T) {
	h := newHost()
	if migrated, err := newInstaller(h).Migrate(context.Background(), "/var/lib/vnm"); migrated || err != nil {
		t.Fatalf("clean node: %t %v", migrated, err)
	}
}

func TestInstallWarpReusesRegistration(t *testing.T) {
	h := newHost()
	h.registed = true
	res, err := newInstaller(h).InstallWarp(context.Background(), layout, "")
	if err != nil || res.Registered || slices.Contains(h.log, "wgcf register") || !slices.Contains(h.log, "exit conf") {
		t.Fatalf("res %+v err %v log %v", res, err, h.log)
	}
}

// Removing a hand-made WARP is irreversible: without the tool to replace it,
// it stays.
func TestInstallWarpEnsuresToolBeforeMigrating(t *testing.T) {
	h := legacyNode()
	h.fail["wgcf tool"] = errors.New("download failed")
	if _, err := newInstaller(h).InstallWarp(context.Background(), layout, ""); err == nil {
		t.Fatal("a failed download was ignored")
	}
	if !h.Exists("/etc/wireguard/warp.conf") || len(h.rules) != 2 {
		t.Fatalf("the old WARP was touched: log %v", h.log)
	}
}

// A license Cloudflare refuses leaves the free account running; anything else
// stops the install.
func TestInstallWarpLicense(t *testing.T) {
	for _, tt := range []struct {
		name    string
		err     error
		refused bool
		fails   bool
	}{
		{"applied", nil, false, false},
		{"refused", fmt.Errorf("%w: 403", install.ErrLicenseNotApplied), true, false},
		{"broken", errors.New("account unreadable"), false, true},
	} {
		h := newHost()
		h.fail["wgcf license"] = tt.err
		res, err := newInstaller(h).InstallWarp(context.Background(), layout, "1a2b3c4d-5e6f7g8h-9i0j1k2l")
		if tt.fails != (err != nil) || tt.refused != (res.LicenseRefused != nil) {
			t.Errorf("%s: res %+v err %v", tt.name, res, err)
		}
		if !tt.fails && !slices.Contains(h.log, "exit conf") {
			t.Errorf("%s: no exit config written: %v", tt.name, h.log)
		}
	}
}

func TestSetupResolver(t *testing.T) {
	h := newHost()
	l := install.Layout{StateDir: "/var/lib/vnm"}
	legacy := "/var/lib/vnm/dns/dnsmasq.conf"
	h.files[legacy] = []byte("port=5353\n")
	h.firewall = "ufw"
	fw, err := newInstaller(h).SetupResolver(context.Background(), l, 5353)
	if err != nil || fw != "ufw" {
		t.Fatalf("firewall %q, err %v", fw, err)
	}
	// The resolver is the vnm binary: no package, only its user — and its
	// port in the host firewall, or redirected DNS from a tunnel is dropped.
	// The host's resolver is never reconfigured.
	if !slices.Equal(h.log, []string{"user " + install.ResolverUser, "remove " + legacy, "allow 5353"}) {
		t.Fatalf("log %v", h.log)
	}
	if _, ok := h.files[legacy]; ok {
		t.Fatal("the config of the dnsmasq the resolver replaced is left behind")
	}
}

// The agent's own tools are installed even with -skip-base: a minimal image
// without nft leaves the agent unable to apply anything.
func TestEnsureTools(t *testing.T) {
	h := newHost()
	if err := newInstaller(h).EnsureTools(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(h.log, "apt nftables") {
		t.Fatalf("log %v", h.log)
	}
}

// firewalld rejects forwarding to an interface outside its zones: every exit
// is let in, or tunnel clients find the exit's destinations unreachable.
func TestAllowExitForwarding(t *testing.T) {
	h := newHost()
	h.firewall = "firewalld"
	fw, err := newInstaller(h).AllowExitForwarding(context.Background(), []string{"warp"})
	if err != nil || fw != "firewalld" || !slices.Equal(h.log, []string{"forward warp"}) {
		t.Fatalf("firewall %q err %v log %v", fw, err, h.log)
	}
}

func TestStartRestartsRunningAgent(t *testing.T) {
	h := newHost()
	h.active[install.AgentUnit] = true
	if err := newInstaller(h).Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(h.log, "restart "+install.AgentUnit) {
		t.Fatalf("log %v: a running agent must pick up the new binary", h.log)
	}
}

// A reissue registers a new account, carries the WARP+ license over and
// rewrites the exit config.
func TestReissueWarp(t *testing.T) {
	h := newHost()
	h.registed, h.license = true, "1a2b3c4d-5e6f7g8h-9i0j1k2l"
	res, err := newInstaller(h).ReissueWarp(context.Background())
	if err != nil || !res.Registered || !res.Plus {
		t.Fatalf("res %+v err %v", res, err)
	}
	want := []string{"wgcf tool", "wgcf retire", "wgcf register", "wgcf license", "exit conf"}
	if !slices.Equal(h.log, want) {
		t.Fatalf("log %v, want %v", h.log, want)
	}
}

// A registration that fails puts the old account back: a node is better off
// with a broken account than with none.
func TestReissueWarpRestoresOnFailure(t *testing.T) {
	h := newHost()
	h.registed = true
	h.fail["wgcf register"] = errors.New("cloudflare: 429")
	if _, err := newInstaller(h).ReissueWarp(context.Background()); err == nil {
		t.Fatal("a failed registration was reported as success")
	}
	if !h.registed || !slices.Contains(h.log, "wgcf restore") || slices.Contains(h.log, "exit conf") {
		t.Fatalf("registered %t, log %v", h.registed, h.log)
	}
}
