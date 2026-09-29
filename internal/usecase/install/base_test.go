package install_test

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/lib4u/vnm/internal/usecase/install"
)

const (
	hardening    = "/etc/ssh/sshd_config.d/00-hardening.conf"
	applySession = "/var/lib/vnm/ssh-apply-session"
	rollback     = "schedule vnm-ssh-rollback 5m0s"
)

func TestBaseIsIdempotentAndArmsSSHRollback(t *testing.T) {
	h := newHost()
	h.ram = 957 // every step has work to do
	in := newInstaller(h)
	res, err := in.Base(context.Background(), layout, nil)
	if err != nil {
		t.Fatalf("Base: %v", err)
	}
	if !res.ConfirmSSH || !slices.Contains(h.log, rollback) {
		t.Fatalf("result %+v, log %v: the SSH change must roll back unless confirmed", res, h.log)
	}
	// The rollback is armed before sshd reloads the new config, and after
	// every other step: apt waiting for the dpkg lock must not eat the window.
	armed := slices.Index(h.log, rollback)
	for _, before := range []string{"apt fail2ban", "sysctl", "swap /swapfile"} {
		if i := slices.Index(h.log, before); i < 0 || i > armed {
			t.Fatalf("log %v: %q after the rollback was armed", h.log, before)
		}
	}
	if armed > slices.Index(h.log, "reload ssh") {
		t.Fatalf("log %v: rollback armed after the reload", h.log)
	}
	if strings.TrimSpace(string(h.files[applySession])) != h.session {
		t.Fatalf("applying session recorded as %q", h.files[applySession])
	}

	h.log = nil
	res, err = in.Base(context.Background(), layout, nil)
	if err != nil || len(res.Changed) != 0 || !slices.Equal(h.log, []string{"apt fail2ban"}) {
		t.Fatalf("second run: %+v %v, log %v", res, err, h.log)
	}
	// Still pending: the operator is reminded to confirm.
	if !res.ConfirmSSH {
		t.Fatal("second run forgot the pending confirmation")
	}
}

// Without a key that logs root in, turning passwords off would lock root out.
func TestBaseNeedsUsableKey(t *testing.T) {
	const stub = `no-port-forwarding,no-agent-forwarding,no-X11-forwarding,command="echo 'Please login as the user \"ubuntu\" rather than the user \"root\".';echo;sleep 10;exit 142" ssh-rsa AAAAB3 root@cloud`
	for _, tt := range []struct {
		name, keys string
		usable     bool
	}{
		{"plain key", "ssh-ed25519 AAAA op@host", true},
		{"comment only", "# no keys", false},
		{"cloud-init stub", stub, false},
		{"stub and a key", stub + "\nssh-ed25519 AAAA op@host", true},
		{"options without command", `from="203.0.113.0/24",no-pty ssh-ed25519 AAAA op`, true},
		{"command in capitals", `COMMAND="/bin/false" ssh-ed25519 AAAA op`, false},
		{"command inside a quoted option", `from="a,command=x" ssh-ed25519 AAAA op`, true},
		{"command in the comment", "ssh-ed25519 AAAA command=x", true},
	} {
		h := newHost()
		h.files["/root/.ssh/authorized_keys"] = []byte(tt.keys + "\n")
		_, err := newInstaller(h).Base(context.Background(), layout, nil)
		if tt.usable != (err == nil) || !tt.usable && (!errors.Is(err, install.ErrNoAuthorizedKeys) || h.Exists(hardening)) {
			t.Errorf("%s: err %v, hardening written %t", tt.name, err, h.Exists(hardening))
		}
	}
}

// Hardening that could not be armed and loaded is taken back, or it would take
// effect unconfirmed at the next reboot; the next run starts over.
func TestBaseSSHFailureRemovesDropIn(t *testing.T) {
	for _, failing := range []string{rollback, "reload ssh"} {
		h := newHost()
		h.fail[failing] = errors.New("failed")
		in := newInstaller(h)
		if _, err := in.Base(context.Background(), layout, nil); err == nil {
			t.Fatalf("%s: no error", failing)
		}
		if h.Exists(hardening) || h.scheduled["vnm-ssh-rollback"] {
			t.Fatalf("%s: drop-in %t, rollback pending %t", failing, h.Exists(hardening), h.scheduled["vnm-ssh-rollback"])
		}
		delete(h.fail, failing)
		if res, err := in.Base(context.Background(), layout, nil); err != nil || !res.ConfirmSSH {
			t.Fatalf("%s: rerun %+v %v", failing, res, err)
		}
	}
}

// A step is judged by the host's state, not by whether its file changed: a
// run after a failure, or after someone undid a step, finishes it.
func TestBaseFinishesWhatIsNotInEffect(t *testing.T) {
	for _, tt := range []struct {
		name    string
		fail    string      // fails on the first run
		between func(*host) // changes the host between the runs
		want    string      // happens on the second run
	}{
		{name: "fail2ban restart failed", fail: "restart fail2ban", want: "restart fail2ban"},
		{name: "fail2ban stopped", between: func(h *host) { h.active["fail2ban"] = false }, want: "enable fail2ban"},
		{name: "sysctl reload failed", fail: "sysctl", want: "sysctl"},
		{name: "sysctl value reset", between: func(h *host) { h.sysctl["net.ipv4.tcp_congestion_control"] = "cubic" }, want: "sysctl"},
		{name: "swapon failed", fail: "swap /swapfile", want: "swap /swapfile"},
	} {
		h := newHost()
		h.ram = 957
		if tt.fail != "" {
			h.fail[tt.fail] = errors.New("failed")
		}
		in := newInstaller(h)
		if _, err := in.Base(context.Background(), layout, nil); (err != nil) != (tt.fail != "") {
			t.Fatalf("%s: first run: %v", tt.name, err)
		}
		delete(h.fail, tt.fail)
		if tt.between != nil {
			tt.between(h)
		}
		h.log = nil
		if _, err := in.Base(context.Background(), layout, nil); err != nil || !slices.Contains(h.log, tt.want) {
			t.Fatalf("%s: second run %v, log %v", tt.name, err, h.log)
		}
	}
}

func TestConfirmBase(t *testing.T) {
	const other = "203.0.113.7 50023 198.51.100.1 22"
	for _, tt := range []struct {
		name    string
		setup   func(*host)
		want    error
		pending bool // the rollback is still pending afterwards
	}{
		{name: "new session", setup: func(h *host) { h.session = other }},
		{name: "same session", setup: func(*host) {}, want: install.ErrNotNewSession, pending: true},
		{name: "outside SSH", setup: func(h *host) { h.session = "" }, want: install.ErrNotNewSession, pending: true},
		{name: "already kept", setup: func(h *host) { h.session = other; delete(h.scheduled, "vnm-ssh-rollback") }, want: install.ErrNothingToConfirm},
		{name: "rolled back", setup: func(h *host) {
			h.session = other
			delete(h.scheduled, "vnm-ssh-rollback")
			delete(h.files, hardening)
		}, want: install.ErrNothingToConfirm},
	} {
		h := newHost()
		in := newInstaller(h)
		if _, err := in.Base(context.Background(), layout, nil); err != nil {
			t.Fatal(err)
		}
		tt.setup(h)
		err := in.ConfirmBase(context.Background(), layout)
		if tt.want == nil && err != nil || tt.want != nil && !errors.Is(err, tt.want) {
			t.Errorf("%s: err %v, want %v", tt.name, err, tt.want)
		}
		if h.scheduled["vnm-ssh-rollback"] != tt.pending {
			t.Errorf("%s: rollback pending %t", tt.name, h.scheduled["vnm-ssh-rollback"])
		}
		if tt.want == nil && h.Exists(applySession) {
			t.Errorf("%s: session record left", tt.name)
		}
	}
}

// Tunnel subnets are never banned (installer §1): SSH from inside a VPN
// arrives from the tunnel's address.
func TestFail2banJailIgnoresTunnels(t *testing.T) {
	jail := string(install.Fail2banJail([]netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}))
	for _, want := range []string{"10.77.0.0/16", "198.51.100.0/24"} {
		if !strings.Contains(jail, want) {
			t.Errorf("ignoreip lacks %s:\n%s", want, jail)
		}
	}
	if strings.Contains(jail, "10.0.0.0/8") {
		t.Errorf("ignoreip trusts all of 10/8:\n%s", jail)
	}
}

func TestSwapOnlyWhereNeeded(t *testing.T) {
	for _, tt := range []struct {
		ram, swap int
		want      bool
	}{
		{957, 0, true}, {1967, 512, true}, {1967, 2047, false}, {4096, 0, false},
	} {
		if got := install.NeedsSwap(tt.ram, tt.swap); got != tt.want {
			t.Errorf("NeedsSwap(%d, %d) = %t", tt.ram, tt.swap, got)
		}
	}
}

// The sysctl must not narrow the ephemeral range: the listen-port safety net
// tells UDP servers from clients by it.
func TestSysctlLeavesEphemeralRange(t *testing.T) {
	if strings.Contains(string(install.Sysctl()), "ip_local_port_range") {
		t.Fatal("sysctl sets ip_local_port_range")
	}
}

// The OpenSSH unit is the distribution's: sshd on AlmaLinux, where there is
// no ssh.service — in the reload and in the rollback alike.
func TestSSHUnitOfTheDistribution(t *testing.T) {
	h := newHost()
	h.sshUnit = "sshd"
	h.files["/root/.ssh/authorized_keys"] = []byte("ssh-ed25519 AAAA operator\n")
	h.session = "203.0.113.9 50000 192.0.2.1 22"
	if _, err := newInstaller(h).Base(context.Background(), layout, nil); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(h.log, "reload sshd") || slices.Contains(h.log, "reload ssh") {
		t.Fatalf("log %v", h.log)
	}
}
