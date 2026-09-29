// Package install sets a node up for vnm (docs/vpn-node-manager-installer.md):
// the base layer, the WARP exit, migration from a hand-made WARP, and the
// agent's files and units.
//
// Unlike the agent, the installer knows about WARP — it registers the exit —
// but it too acts on the host only through the ports below, so every decision
// is testable without a host.
package install

import (
	"context"
	"os"
	"time"

	"github.com/lib4u/vnm/internal/domain/netstate"
)

// Files is the host's filesystem.
type Files interface {
	// Write replaces path atomically and reports whether the content changed.
	Write(path string, data []byte, mode os.FileMode) (changed bool, err error)
	// Read fails with fs.ErrNotExist for a missing file.
	Read(path string) ([]byte, error)
	Exists(path string) bool
	// Remove deletes a file or a directory tree; a missing one is not an error.
	Remove(path string) error
}

// Packages installs distribution packages, waiting for the package manager's
// lock (unattended-upgrades holds it for minutes on a fresh node).
type Packages interface {
	Install(ctx context.Context, names ...string) error
}

// Services is systemd.
type Services interface {
	DaemonReload(ctx context.Context) error
	EnableNow(ctx context.Context, units ...string) error
	Restart(ctx context.Context, unit string) error
	Reload(ctx context.Context, unit string) error
	// DisableNow stops and disables a unit; a missing unit is not an error.
	DisableNow(ctx context.Context, unit string) error
	Enabled(ctx context.Context, unit string) bool
	Active(ctx context.Context, unit string) bool
	// Schedule runs a command once after a delay, under a named transient
	// unit, unless Cancel is called first. It is the auto-rollback of the
	// changes that can lock the operator out.
	Schedule(ctx context.Context, name string, after time.Duration, command ...string) error
	// Scheduled reports whether the command scheduled under name is still
	// waiting to run.
	Scheduled(ctx context.Context, name string) bool
	Cancel(ctx context.Context, name string) error
}

// Host holds facts about the machine and the actions without a better home.
type Host interface {
	OSRelease() (id, version string, err error)
	// Arch is the machine's architecture in GOARCH terms.
	Arch() string
	MemoryMB() (ram, swap int, err error)
	// Sysctl reads the live value of a kernel parameter; one that does not
	// exist (its module is not loaded) fails with fs.ErrNotExist.
	Sysctl(key string) (string, error)
	ReloadSysctl(ctx context.Context) error
	CheckSSHD(ctx context.Context) error
	// SwapActive reports whether the swap file at path is in use.
	SwapActive(path string) (bool, error)
	// AddSwap creates, enables and persists a swap file; a file left over by
	// an earlier failed attempt is reused.
	AddSwap(ctx context.Context, path string, sizeMB int) error
	// SSHConnection identifies the SSH connection the command runs in —
	// client address and port, as $SSH_CONNECTION has them — or is empty
	// outside SSH.
	SSHConnection() string
	// Executable is the path of the running binary.
	Executable() (string, error)
	// SSHUnit is the OpenSSH server's systemd unit on this distribution.
	SSHUnit() string
	// AllowPort lets a port in, over TCP and UDP, through the active host
	// firewall (ufw or firewalld) and names it; with none active it does
	// nothing and returns "".
	AllowPort(ctx context.Context, port uint16, comment string) (firewall string, err error)
	// AllowForwardTo lets forwarded traffic out through an interface in the
	// active host firewall, where that firewall restricts it (firewalld), and
	// names it; otherwise it does nothing and returns "".
	AllowForwardTo(ctx context.Context, iface string) (firewall string, err error)
	// EnsureSystemUser creates a system user without a home or a login
	// shell; an existing one is left as it is.
	EnsureSystemUser(ctx context.Context, name string) error
}

// Warp is the node's WARP registration.
type Warp interface {
	EnsureTool(ctx context.Context) error
	Registered() bool
	Register(ctx context.Context) error
	// ApplyLicense reports whether the account became WARP+. A license
	// Cloudflare refuses leaves the account as it was and fails with
	// ErrLicenseNotApplied: the free account keeps working.
	ApplyLicense(ctx context.Context, key string) (plus bool, err error)
	// License is the WARP+ license applied to this node; "" when none was.
	License() (string, error)
	// Retire moves the account aside for a new registration; restore puts
	// it back.
	Retire(ctx context.Context) (restore func() error, err error)
	WriteExitConf(ctx context.Context) error
}

// Rules are the policy routing rules in the owned priority range.
type Rules interface {
	Rules(ctx context.Context) ([]netstate.IPRule, error)
	AddRule(ctx context.Context, r netstate.IPRule) error
	DeleteRule(ctx context.Context, r netstate.IPRule) error
}
