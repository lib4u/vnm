package install

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"path/filepath"
	"strings"
	"time"
)

// Files and units of the base layer.
const (
	sshdHardening  = "/etc/ssh/sshd_config.d/00-hardening.conf"
	authorizedKeys = "/root/.ssh/authorized_keys"
	fail2banJail   = "/etc/fail2ban/jail.d/vnm-sshd.local"
	fail2banUnit   = "fail2ban"
	sysctlFile     = "/etc/sysctl.d/99-vnm.conf"
	conntrackLoad  = "/etc/modules-load.d/vnm-conntrack.conf"
	swapFile       = "/swapfile"
	swapSizeMB     = 2048

	// sshRollback is the transient unit that undoes the SSH hardening unless
	// the operator confirms from a new session.
	sshRollback = "vnm-ssh-rollback"
	// sshSession, in the state directory, records the SSH connection that
	// applied the hardening: the confirmation must come from another one.
	sshSession = "ssh-apply-session"
)

// SSHConfirmWindow is how long the operator has to confirm the SSH hardening.
const SSHConfirmWindow = 5 * time.Minute

// tunnelRange holds the private tunnel subnets fail2ban never bans
// (installer §1).
var tunnelRange = netip.MustParsePrefix("10.77.0.0/16")

var (
	// ErrNoAuthorizedKeys means disabling password login would lock root out.
	ErrNoAuthorizedKeys = errors.New("root has no authorized SSH keys; password login stays on")
	// ErrNothingToConfirm means no SSH hardening awaits confirmation.
	ErrNothingToConfirm = errors.New("no SSH hardening awaits confirmation")
	// ErrNotNewSession means the confirmation does not come from a new SSH
	// session, so it proves nothing about key login.
	ErrNotNewSession = errors.New("confirm from a new SSH session")
)

// BaseResult says what the base step changed and what the operator must do.
type BaseResult struct {
	Changed []string
	// ConfirmSSH means the SSH hardening rolls itself back unless
	// `vnm base confirm` is run from a new SSH session.
	ConfirmSSH bool
}

// Base applies the base layer: fail2ban, sysctl, swap, and SSH by key only.
// Every part is idempotent on the host's actual state — a second run changes
// nothing, and a run after a failure finishes what the failed one left.
//
// SSH goes last: its rollback timer starts when it is applied, and apt waiting
// for the dpkg lock must not eat the operator's window to confirm.
func (in *Installer) Base(ctx context.Context, l Layout, trusted []netip.Prefix) (BaseResult, error) {
	var res BaseResult
	note := func(changed bool, what string) {
		if changed {
			res.Changed = append(res.Changed, what)
		}
	}

	changed, err := in.fail2ban(ctx, trusted)
	if err != nil {
		return res, fmt.Errorf("fail2ban: %w", err)
	}
	note(changed, "fail2ban: sshd jail")

	changed, err = in.sysctl(ctx)
	if err != nil {
		return res, fmt.Errorf("sysctl: %w", err)
	}
	note(changed, "sysctl: network tuning")

	changed, err = in.swap(ctx)
	if err != nil {
		return res, fmt.Errorf("swap: %w", err)
	}
	note(changed, "swap: 2 GiB swapfile")

	changed, err = in.hardenSSH(ctx, l)
	if err != nil {
		return res, fmt.Errorf("ssh: %w", err)
	}
	note(changed, "ssh: password login off")
	res.ConfirmSSH = in.svc.Scheduled(ctx, sshRollback)
	return res, nil
}

// ConfirmBase keeps the SSH hardening. It must run from a new SSH session —
// which proves key login works — while the rollback is still pending.
func (in *Installer) ConfirmBase(ctx context.Context, l Layout) error {
	if !in.svc.Scheduled(ctx, sshRollback) {
		if !in.files.Exists(sshdHardening) {
			return fmt.Errorf("%w: it was rolled back, run `vnm base apply` again", ErrNothingToConfirm)
		}
		return fmt.Errorf("%w: no rollback is pending, the hardening is already kept", ErrNothingToConfirm)
	}
	current := in.host.SSHConnection()
	if current == "" {
		return fmt.Errorf("%w: this is not an SSH session (sudo drops $SSH_CONNECTION: keep it with --preserve-env=SSH_CONNECTION)", ErrNotNewSession)
	}
	session := filepath.Join(l.StateDir, sshSession)
	applied, err := in.files.Read(session)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if strings.TrimSpace(string(applied)) == current {
		return fmt.Errorf("%w: this session applied the hardening; open a new SSH connection and confirm from there", ErrNotNewSession)
	}
	if err := in.svc.Cancel(ctx, sshRollback); err != nil {
		return err
	}
	if !in.files.Exists(sshdHardening) {
		return fmt.Errorf("%w: it was rolled back just now, run `vnm base apply` again", ErrNothingToConfirm)
	}
	return in.files.Remove(session)
}

// hardenSSH turns password login off. The drop-in's name starts with 00-
// because sshd takes the first value it reads and cloud-init's 50- file turns
// passwords on. A change is armed with an automatic rollback; if arming or the
// reload fails, the drop-in goes too, so that an unconfirmed change cannot
// take effect at the next reboot and the next run starts over.
func (in *Installer) hardenSSH(ctx context.Context, l Layout) (bool, error) {
	keys, err := in.files.Read(authorizedKeys)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, err
	}
	if !hasKey(keys) {
		return false, ErrNoAuthorizedKeys
	}
	changed, err := in.files.Write(sshdHardening, SSHDHardening(), 0o644)
	if err != nil || !changed {
		return false, err
	}
	session := filepath.Join(l.StateDir, sshSession)
	if err := in.armSSH(ctx, session); err != nil {
		return false, errors.Join(err,
			in.svc.Cancel(ctx, sshRollback), in.files.Remove(sshdHardening), in.files.Remove(session))
	}
	return true, nil
}

// armSSH checks the new sshd config, schedules its rollback and reloads sshd.
func (in *Installer) armSSH(ctx context.Context, session string) error {
	if err := in.host.CheckSSHD(ctx); err != nil {
		return fmt.Errorf("sshd rejects the drop-in: %w", err)
	}
	if _, err := in.files.Write(session, []byte(in.host.SSHConnection()+"\n"), 0o600); err != nil {
		return err
	}
	unit := in.host.SSHUnit()
	err := in.svc.Schedule(ctx, sshRollback, SSHConfirmWindow,
		"/bin/sh", "-c", "rm -f "+sshdHardening+" "+session+" && systemctl reload "+unit)
	if err != nil {
		return fmt.Errorf("schedule the rollback: %w", err)
	}
	return in.svc.Reload(ctx, unit)
}

// hasKey reports whether authorized_keys holds a key that logs root in.
func hasKey(authorized []byte) bool {
	for line := range strings.SplitSeq(string(authorized), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") && !forcedCommand(line) {
			return true
		}
	}
	return false
}

// forcedCommand reports whether an authorized_keys line carries a command=
// option. Such a key runs that command instead of a shell — cloud-init puts
// one on root that only says "Please login as the user ubuntu" — so it does
// not count as a way in.
func forcedCommand(line string) bool {
	if isKeyType(strings.Fields(line)[0]) {
		return false // no options
	}
	quoted, start := false, 0
	for i := 0; i < len(line); i++ {
		switch c := line[i]; {
		case quoted && c == '\\':
			i++
		case c == '"':
			quoted = !quoted
		case !quoted && (c == ',' || c == ' ' || c == '\t'):
			if name, _, _ := strings.Cut(line[start:i], "="); strings.EqualFold(name, "command") {
				return true
			}
			if c != ',' {
				return false // the options end at the first blank outside quotes
			}
			start = i + 1
		}
	}
	return false
}

// isKeyType reports whether a field is a key type rather than options.
func isKeyType(field string) bool {
	for _, prefix := range []string{"ssh-", "ecdsa-", "sk-"} {
		if strings.HasPrefix(field, prefix) {
			return true
		}
	}
	return false
}

// fail2ban installs the sshd jail and keeps fail2ban enabled and running. A
// jail it failed to load is removed, so the next run writes and loads it again.
func (in *Installer) fail2ban(ctx context.Context, trusted []netip.Prefix) (bool, error) {
	if err := in.pkgs.Install(ctx, "fail2ban"); err != nil {
		return false, err
	}
	changed, err := in.files.Write(fail2banJail, Fail2banJail(trusted), 0o644)
	if err != nil {
		return false, err
	}
	running := in.svc.Enabled(ctx, fail2banUnit) && in.svc.Active(ctx, fail2banUnit)
	if !changed && running {
		return false, nil
	}
	err = in.svc.EnableNow(ctx, fail2banUnit)
	if err == nil && changed {
		err = in.svc.Restart(ctx, fail2banUnit)
	}
	if err != nil {
		return false, errors.Join(err, in.files.Remove(fail2banJail))
	}
	return true, nil
}

// sysctl writes the tuning and applies it unless every value is already live.
func (in *Installer) sysctl(ctx context.Context) (bool, error) {
	loadChanged, err := in.files.Write(conntrackLoad, []byte("nf_conntrack\n"), 0o644)
	if err != nil {
		return false, err
	}
	changed, err := in.files.Write(sysctlFile, Sysctl(), 0o644)
	if err != nil {
		return false, err
	}
	if !changed && !loadChanged && in.sysctlLive() {
		return false, nil
	}
	return true, in.host.ReloadSysctl(ctx)
}

// sysctlLive reports whether the kernel runs with every value of Sysctl. A
// value it cannot read — conntrack's before the module is loaded — is not.
func (in *Installer) sysctlLive() bool {
	for line := range strings.Lines(string(Sysctl())) {
		key, want, ok := strings.Cut(line, "=")
		if !ok || strings.HasPrefix(line, "#") {
			continue
		}
		got, err := in.host.Sysctl(strings.TrimSpace(key))
		if err != nil || strings.Join(strings.Fields(got), " ") != strings.Join(strings.Fields(want), " ") {
			return false
		}
	}
	return true
}

// swap adds a 2 GiB swapfile to a machine under 2 GiB of RAM with less than
// 1 GiB of swap: the OOM killer on a 1 GiB node takes out the tunnels first.
// A swapfile already in use but smaller is someone else's and is left alone.
func (in *Installer) swap(ctx context.Context) (bool, error) {
	ram, swap, err := in.host.MemoryMB()
	if err != nil {
		return false, err
	}
	if !NeedsSwap(ram, swap) {
		return false, nil
	}
	active, err := in.host.SwapActive(swapFile)
	if err != nil || active {
		return false, err
	}
	return true, in.host.AddSwap(ctx, swapFile, swapSizeMB)
}

// NeedsSwap reports whether a machine should get a swapfile.
func NeedsSwap(ramMB, swapMB int) bool {
	return ramMB < 2048 && swapMB < 1024
}

// SSHDHardening is the sshd drop-in: keys only.
func SSHDHardening() []byte {
	return []byte("# vnm base (docs/vpn-node-manager-installer.md §1): keys only.\n" +
		"PasswordAuthentication no\n" +
		"KbdInteractiveAuthentication no\n" +
		"PermitRootLogin prohibit-password\n")
}

// Fail2banJail is the sshd jail. Trusted ranges — management, private tunnel
// subnets — are never banned: SSH from inside a tunnel arrives from the
// tunnel's address, and banning it helps nobody.
func Fail2banJail(trusted []netip.Prefix) []byte {
	ignore := []string{"127.0.0.1/8", "::1", tunnelRange.String()}
	for _, p := range trusted {
		ignore = append(ignore, p.String())
	}
	var b bytes.Buffer
	b.WriteString("# vnm base (docs/vpn-node-manager-installer.md §1).\n")
	b.WriteString("[sshd]\nenabled = true\nbackend = systemd\n")
	b.WriteString("maxretry = 4\nfindtime = 10m\nbantime = 1h\n")
	b.WriteString("bantime.increment = true\nbantime.maxtime = 1w\n")
	fmt.Fprintf(&b, "ignoreip = %s\n", strings.Join(ignore, " "))
	return b.Bytes()
}

// Sysctl is the network tuning of installer §1. The ephemeral port range is
// deliberately left alone: the listen-port safety net tells servers from
// clients by it, and widening it downwards would hide UDP services.
func Sysctl() []byte {
	return []byte(`# vnm base (docs/vpn-node-manager-installer.md §1).
# Speed on lossy paths to Russia.
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1
# UDP headroom for QUIC and hysteria; ceilings only.
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.ipv4.tcp_rmem = 4096 131072 33554432
net.ipv4.tcp_wmem = 4096 16384 16777216
# Connection capacity.
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 32768
net.ipv4.tcp_max_syn_backlog = 16384
fs.file-max = 1048576
# Conntrack: the default 7680 on a 1 GiB node made 443 answer every other time;
# connections cut without FIN by DPI held entries for five days.
net.netfilter.nf_conntrack_max = 262144
net.netfilter.nf_conntrack_buckets = 65536
net.netfilter.nf_conntrack_tcp_timeout_established = 600
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 30
`)
}
