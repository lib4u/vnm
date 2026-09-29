// Package system is the host as the installer sees it: files, apt, systemd and
// a few facts about the machine.
package system

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/lib4u/vnm/internal/infrastructure/atomicfile"
	"github.com/lib4u/vnm/internal/infrastructure/runner"
	"github.com/lib4u/vnm/internal/usecase/install"
)

// aptLockTimeout is how long apt waits for the dpkg lock; unattended-upgrades
// holds it for about ten minutes on a fresh node.
const aptLockTimeout = 15 * time.Minute

// System implements the installer's host ports.
type System struct {
	run runner.Runner
}

var (
	_ install.Files    = (*System)(nil)
	_ install.Packages = (*System)(nil)
	_ install.Services = (*System)(nil)
	_ install.Host     = (*System)(nil)
)

// New returns a System running commands through run.
func New(run runner.Runner) *System {
	return &System{run: run}
}

func (s *System) cmd(ctx context.Context, name string, args ...string) (string, error) {
	return s.run.Run(ctx, runner.Command{Name: name, Args: args})
}

// Write replaces path atomically unless it already holds data.
func (s *System) Write(path string, data []byte, mode os.FileMode) (bool, error) {
	if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, data) {
		if info, err := os.Stat(path); err == nil && info.Mode().Perm() == mode {
			return false, nil
		}
	}
	return true, atomicfile.WriteFile(path, data, mode)
}

// Read reads a file.
func (s *System) Read(path string) ([]byte, error) { return os.ReadFile(path) }

// Exists reports whether path exists.
func (s *System) Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// Remove deletes a file or a tree; a missing path is not an error.
func (s *System) Remove(path string) error { return os.RemoveAll(path) }

// Install installs packages that are not installed yet.
func (s *System) Install(ctx context.Context, names ...string) error {
	if s.redHat() {
		return s.dnfInstall(ctx, names)
	}
	var missing []string
	for _, name := range names {
		status, err := s.cmd(ctx, "dpkg-query", "-W", "-f=${Status}", name)
		if err != nil || !strings.Contains(status, "install ok installed") {
			missing = append(missing, name)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	lock := fmt.Sprintf("DPkg::Lock::Timeout=%d", int(aptLockTimeout.Seconds()))
	if _, err := s.cmd(ctx, "apt-get", "-o", lock, "update", "-qq"); err != nil {
		return fmt.Errorf("apt update: %w", err)
	}
	args := append([]string{"-o", lock, "install", "-y", "-qq"}, missing...)
	if _, err := s.run.Run(ctx, runner.Command{Name: "apt-get", Args: args}); err != nil {
		return fmt.Errorf("apt install %v: %w", missing, err)
	}
	return nil
}

// DaemonReload reloads unit files.
func (s *System) DaemonReload(ctx context.Context) error {
	_, err := s.cmd(ctx, "systemctl", "daemon-reload")
	return err
}

// EnableNow enables and starts units.
func (s *System) EnableNow(ctx context.Context, units ...string) error {
	_, err := s.cmd(ctx, "systemctl", append([]string{"enable", "--now"}, units...)...)
	return err
}

// Restart restarts a unit.
func (s *System) Restart(ctx context.Context, unit string) error {
	_, err := s.cmd(ctx, "systemctl", "restart", unit)
	return err
}

// Reload reloads a unit.
func (s *System) Reload(ctx context.Context, unit string) error {
	_, err := s.cmd(ctx, "systemctl", "reload", unit)
	return err
}

// DisableNow stops and disables a unit that exists.
func (s *System) DisableNow(ctx context.Context, unit string) error {
	state, err := s.cmd(ctx, "systemctl", "show", "-p", "LoadState", "--value", unit)
	if err != nil {
		return fmt.Errorf("read state of %s: %w", unit, err)
	}
	if strings.TrimSpace(state) == "not-found" {
		return nil // a unit that does not exist is disabled
	}
	_, err = s.cmd(ctx, "systemctl", "disable", "--now", unit)
	return err
}

// Enabled reports whether a unit is enabled.
func (s *System) Enabled(ctx context.Context, unit string) bool {
	_, err := s.cmd(ctx, "systemctl", "is-enabled", "--quiet", unit)
	return err == nil
}

// ForwardPolicy returns the policy of the iptables filter FORWARD chain:
// "ACCEPT" or "DROP".
func (s *System) ForwardPolicy(ctx context.Context) (string, error) {
	out, err := s.cmd(ctx, "iptables", "-S", "FORWARD")
	if err != nil {
		return "", err
	}
	for line := range strings.Lines(out) {
		if pol, ok := strings.CutPrefix(strings.TrimSpace(line), "-P FORWARD "); ok {
			return pol, nil
		}
	}
	return "", errors.New("iptables printed no FORWARD policy")
}

// The host firewalls whose default is to drop what they do not allow.
const (
	firewallUFW       = "ufw"
	firewallFirewalld = "firewalld"
)

// hostFirewall returns the active host firewall: "ufw", "firewalld" or "".
func (s *System) hostFirewall(ctx context.Context) string {
	if out, err := s.cmd(ctx, "ufw", "status"); err == nil && strings.HasPrefix(strings.TrimSpace(out), "Status: active") {
		return firewallUFW
	}
	if out, err := s.cmd(ctx, "firewall-cmd", "--state"); err == nil && strings.TrimSpace(out) == "running" {
		return firewallFirewalld
	}
	return ""
}

// AllowPort lets a port in, over TCP and UDP, through the active host
// firewall, and reports which one that was; with none active it does nothing.
func (s *System) AllowPort(ctx context.Context, port uint16, comment string) (string, error) {
	fw := s.hostFirewall(ctx)
	p := strconv.Itoa(int(port))
	var err error
	switch fw {
	case firewallUFW:
		_, err = s.cmd(ctx, "ufw", "allow", p, "comment", comment)
	case firewallFirewalld:
		ports := []string{"--add-port=" + p + "/udp", "--add-port=" + p + "/tcp"}
		if _, err = s.cmd(ctx, "firewall-cmd", append([]string{"--permanent"}, ports...)...); err == nil {
			_, err = s.cmd(ctx, "firewall-cmd", ports...)
		}
	}
	return fw, err
}

// AllowForwardTo lets forwarded traffic out through an interface in the active
// host firewall and reports which one that was. Only firewalld needs it: it
// forwards only to interfaces of a zone, and rejects the rest with
// admin-prohibited, so an exit outside every zone is unreachable for tunnel
// clients. The interface joins the default zone — the uplink's — unless the
// operator already put it in one.
func (s *System) AllowForwardTo(ctx context.Context, iface string) (string, error) {
	if s.hostFirewall(ctx) != firewallFirewalld {
		return "", nil
	}
	if zone, err := s.cmd(ctx, "firewall-cmd", "--get-zone-of-interface="+iface); err == nil && strings.TrimSpace(zone) != "" {
		return firewallFirewalld, nil
	}
	zone, err := s.cmd(ctx, "firewall-cmd", "--get-default-zone")
	if err != nil {
		return firewallFirewalld, err
	}
	add := []string{"--zone=" + strings.TrimSpace(zone), "--add-interface=" + iface}
	if _, err := s.cmd(ctx, "firewall-cmd", append([]string{"--permanent"}, add...)...); err != nil {
		return firewallFirewalld, err
	}
	_, err = s.cmd(ctx, "firewall-cmd", add...)
	return firewallFirewalld, err
}

// ForwardAllowedTo reports whether the active host firewall forwards to an
// interface; firewall is "" when none restricts it.
func (s *System) ForwardAllowedTo(ctx context.Context, iface string) (firewall string, allowed bool, err error) {
	if s.hostFirewall(ctx) != firewallFirewalld {
		return "", true, nil
	}
	zone, err := s.cmd(ctx, "firewall-cmd", "--get-zone-of-interface="+iface)
	return firewallFirewalld, err == nil && strings.TrimSpace(zone) != "", nil
}

// PortAllowed reports whether the active host firewall lets a port in over
// UDP; firewall is "" when none is active.
func (s *System) PortAllowed(ctx context.Context, port uint16) (firewall string, allowed bool, err error) {
	fw := s.hostFirewall(ctx)
	p := strconv.Itoa(int(port))
	switch fw {
	case firewallUFW:
		out, err := s.cmd(ctx, "ufw", "status")
		if err != nil {
			return fw, false, err
		}
		for line := range strings.Lines(out) {
			f := strings.Fields(line)
			if len(f) >= 2 && (f[0] == p || f[0] == p+"/udp") && f[1] == "ALLOW" {
				return fw, true, nil
			}
		}
		return fw, false, nil
	case firewallFirewalld:
		_, err := s.cmd(ctx, "firewall-cmd", "--query-port="+p+"/udp")
		return fw, err == nil, nil
	}
	return "", true, nil
}

// Active reports whether a unit is active.
func (s *System) Active(ctx context.Context, unit string) bool {
	_, err := s.cmd(ctx, "systemctl", "is-active", "--quiet", unit)
	return err == nil
}

// Schedule runs a command once after a delay under a transient timer. The
// units are collected even when the command fails: a failed unit left loaded
// would refuse the next schedule under the same name.
func (s *System) Schedule(ctx context.Context, name string, after time.Duration, command ...string) error {
	args := append([]string{"--unit=" + name, "--collect", fmt.Sprintf("--on-active=%d", int(after.Seconds()))}, command...)
	_, err := s.cmd(ctx, "systemd-run", args...)
	return err
}

// Scheduled reports whether the timer of a scheduled command is still waiting:
// an elapsed timer can stay active while its command runs.
func (s *System) Scheduled(ctx context.Context, name string) bool {
	state, err := s.cmd(ctx, "systemctl", "show", "-p", "SubState", "--value", name+".timer")
	return err == nil && strings.TrimSpace(state) == "waiting"
}

// Cancel stops a scheduled command; one that already ran or never existed is
// not an error.
func (s *System) Cancel(ctx context.Context, name string) error {
	if !s.Active(ctx, name+".timer") {
		return nil
	}
	_, err := s.cmd(ctx, "systemctl", "stop", name+".timer")
	return err
}

// OSRelease reads ID and VERSION_ID from /etc/os-release.
func (s *System) OSRelease() (string, string, error) {
	fields, err := osRelease()
	if err != nil {
		return "", "", err
	}
	return fields["ID"], fields["VERSION_ID"], nil
}

func osRelease() (map[string]string, error) {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return nil, err
	}
	fields := keyValues(data, "=")
	for k, v := range fields {
		fields[k] = strings.Trim(v, `"`)
	}
	return fields, nil
}

// redHat reports whether the host is of the Red Hat family (AlmaLinux, Rocky,
// RHEL): dnf and rpm instead of apt and dpkg, sshd instead of ssh.
func (s *System) redHat() bool {
	fields, err := osRelease()
	if err != nil {
		return false
	}
	like := " " + fields["ID"] + " " + fields["ID_LIKE"] + " "
	return strings.Contains(like, " rhel ") || strings.Contains(like, " fedora ")
}

// SSHUnit is the OpenSSH server's unit: ssh on Debian and Ubuntu (where
// 24.04 has no sshd alias), sshd on the Red Hat family.
func (s *System) SSHUnit() string {
	if s.redHat() {
		return "sshd"
	}
	return "ssh"
}

// epelPackages come from EPEL on the Red Hat family.
var epelPackages = map[string]bool{"fail2ban": true}

func (s *System) dnfInstall(ctx context.Context, names []string) error {
	var missing []string
	epel := false
	for _, name := range names {
		if _, err := s.cmd(ctx, "rpm", "-q", name); err != nil {
			missing = append(missing, name)
			epel = epel || epelPackages[name]
		}
	}
	if len(missing) == 0 {
		return nil
	}
	if epel {
		if _, err := s.cmd(ctx, "dnf", "install", "-y", "-q", "epel-release"); err != nil {
			return fmt.Errorf("dnf install epel-release: %w", err)
		}
	}
	args := append([]string{"install", "-y", "-q"}, missing...)
	if _, err := s.run.Run(ctx, runner.Command{Name: "dnf", Args: args}); err != nil {
		return fmt.Errorf("dnf install %v: %w", missing, err)
	}
	return nil
}

// EnsureSystemUser creates a system user with no home and no login shell,
// unless it exists.
func (s *System) EnsureSystemUser(ctx context.Context, name string) error {
	if _, err := user.Lookup(name); err == nil {
		return nil
	}
	_, err := s.cmd(ctx, "useradd", "--system", "--no-create-home", "--home-dir", "/nonexistent",
		"--shell", "/usr/sbin/nologin", "--user-group", name)
	return err
}

// Arch is the architecture the binary was built for, which is the machine's.
func (s *System) Arch() string { return runtime.GOARCH }

// SSHConnection is $SSH_CONNECTION.
func (s *System) SSHConnection() string { return strings.TrimSpace(os.Getenv("SSH_CONNECTION")) }

// MemoryMB reads the RAM and swap sizes.
func (s *System) MemoryMB() (int, int, error) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0, err
	}
	fields := keyValues(data, ":")
	kb := func(key string) (int, error) {
		value, _, _ := strings.Cut(strings.TrimSpace(fields[key]), " ")
		return strconv.Atoi(value)
	}
	ram, errR := kb("MemTotal")
	swap, errS := kb("SwapTotal")
	if err := errors.Join(errR, errS); err != nil {
		return 0, 0, fmt.Errorf("parse /proc/meminfo: %w", err)
	}
	return ram / 1024, swap / 1024, nil
}

// ReloadSysctl loads conntrack, whose settings do not exist until it is
// loaded, and applies every sysctl file.
func (s *System) ReloadSysctl(ctx context.Context) error {
	if _, err := s.cmd(ctx, "modprobe", "nf_conntrack"); err != nil {
		return err
	}
	_, err := s.cmd(ctx, "sysctl", "--system")
	return err
}

// Sysctl reads a kernel parameter from /proc/sys.
func (s *System) Sysctl(key string) (string, error) {
	data, err := os.ReadFile(filepath.Join("/proc/sys", strings.ReplaceAll(key, ".", "/")))
	return strings.TrimSpace(string(data)), err
}

// CheckSSHD validates the sshd configuration.
func (s *System) CheckSSHD(ctx context.Context) error {
	_, err := s.cmd(ctx, "sshd", "-t")
	return err
}

// SwapActive reports whether /proc/swaps lists path.
func (s *System) SwapActive(path string) (bool, error) {
	data, err := os.ReadFile("/proc/swaps")
	if err != nil {
		return false, err
	}
	for line := range strings.Lines(string(data)) {
		if fields := strings.Fields(line); len(fields) > 0 && fields[0] == path {
			return true, nil
		}
	}
	return false, nil
}

// AddSwap creates and persists a swapfile, then turns it on. Every step
// repeats safely on a file an earlier attempt left behind; the fstab line goes
// in before swapon, so a node whose swap is on always has it after a reboot.
func (s *System) AddSwap(ctx context.Context, path string, sizeMB int) error {
	steps := [][]string{
		{"fallocate", "-l", fmt.Sprintf("%dM", sizeMB), path},
		{"chmod", "600", path},
		{"mkswap", path},
	}
	for _, step := range steps {
		if _, err := s.cmd(ctx, step[0], step[1:]...); err != nil {
			return err
		}
	}
	if err := persistSwap(path); err != nil {
		return err
	}
	_, err := s.cmd(ctx, "swapon", path)
	return err
}

// persistSwap adds path to /etc/fstab unless it is there.
func persistSwap(path string) error {
	fstab, err := os.ReadFile("/etc/fstab")
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if bytes.Contains(fstab, []byte(path+" ")) {
		return nil
	}
	line := fmt.Sprintf("%s none swap sw 0 0\n", path)
	return atomicfile.WriteFile("/etc/fstab", append(fstab, []byte(line)...), 0o644)
}

// Executable is the path of the running binary.
func (s *System) Executable() (string, error) { return os.Executable() }

func keyValues(data []byte, sep string) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		if k, v, ok := strings.Cut(sc.Text(), sep); ok {
			out[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return out
}
