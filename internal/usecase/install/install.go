package install

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/template"
)

// ErrUnsupportedOS means the installer refuses the machine without changing it.
var ErrUnsupportedOS = errors.New("unsupported OS")

// ErrLicenseNotApplied means Cloudflare refused a WARP+ license; the account
// stays as it was.
var ErrLicenseNotApplied = errors.New("WARP+ license not applied")

// SupportedOS lists the releases the installer runs on (ТЗ §2): a version
// matches exactly or by its major number ("9" takes AlmaLinux 9.x).
var SupportedOS = map[string][]string{
	"ubuntu":    {"22.04", "24.04", "26.04"},
	"almalinux": {"9"},
}

func supportedOS(id, version string) bool {
	major, _, _ := strings.Cut(version, ".")
	return slices.Contains(SupportedOS[id], version) || slices.Contains(SupportedOS[id], major)
}

// SupportedArch is the one architecture the installer runs on (ТЗ §2): the
// pinned wgcf build is x86_64.
const SupportedArch = "amd64"

// Unit names.
const (
	BootUnit  = "vnm-boot.service"
	AgentUnit = "vnm-agent.service"
	DNSUnit   = "vnm-dns.service"
)

// ResolverUser is the system user vnm-dns.service runs as: its own, so that
// the host's DNS redirect lets exactly its upstream queries through.
const ResolverUser = "vnm-dns"

// Deps are the installer's collaborators.
type Deps struct {
	Files    Files
	Packages Packages
	Services Services
	Host     Host
	Warp     Warp
	Rules    Rules
}

// Installer sets a node up.
type Installer struct {
	files Files
	pkgs  Packages
	svc   Services
	host  Host
	warp  Warp
	rules Rules
}

// New returns an Installer.
func New(d Deps) *Installer {
	return &Installer{files: d.Files, pkgs: d.Packages, svc: d.Services, host: d.Host, warp: d.Warp, rules: d.Rules}
}

// Layout is where an installed node keeps its files. The units are rendered
// from it: a path in a unit is a template field, never a literal.
type Layout struct {
	Binary   string
	UnitDir  string
	Config   string
	StateDir string
	// ConfigMode is the policy file's mode; everything that writes the policy
	// uses the same, or the next write only fixes the mode.
	ConfigMode os.FileMode
}

// ResolverConf is the config the agent writes for the resolver unit.
func (l Layout) ResolverConf() string {
	return filepath.Join(l.StateDir, "dns", "resolver.json")
}

// legacyResolverConf is the config of the dnsmasq the resolver unit ran
// before vnm had a resolver of its own.
func (l Layout) legacyResolverConf() string {
	return filepath.Join(l.StateDir, "dns", "dnsmasq.conf")
}

// Assets are the files the binary carries. The units are text/template
// sources over Layout.
type Assets struct {
	Config    []byte
	BootUnit  []byte
	AgentUnit []byte
	DNSUnit   []byte
}

// Preflight refuses a machine outside SupportedOS and SupportedArch before
// anything is touched.
func (in *Installer) Preflight() error {
	id, version, err := in.host.OSRelease()
	if err != nil {
		return err
	}
	if !supportedOS(id, version) {
		return fmt.Errorf("%w: %s %s (supported: %v)", ErrUnsupportedOS, id, version, SupportedOS)
	}
	if arch := in.host.Arch(); arch != SupportedArch {
		return fmt.Errorf("%w: architecture %s (supported: %s)", ErrUnsupportedOS, arch, SupportedArch)
	}
	return nil
}

// RenderUnit fills a unit template with the layout's paths.
func RenderUnit(name string, src []byte, l Layout) ([]byte, error) {
	t, err := template.New(name).Parse(string(src))
	if err != nil {
		return nil, fmt.Errorf("unit %s: %w", name, err)
	}
	var b bytes.Buffer
	if err := t.Execute(&b, l); err != nil {
		return nil, fmt.Errorf("unit %s: %w", name, err)
	}
	return b.Bytes(), nil
}

// PlaceFiles installs the running binary, the units and — only if there is
// none yet — the config: an operator's edits are never overwritten.
func (in *Installer) PlaceFiles(ctx context.Context, l Layout, a Assets) ([]string, error) {
	if l.ConfigMode == 0 {
		return nil, errors.New("layout has no config mode")
	}
	var changed []string
	self, err := in.host.Executable()
	if err != nil {
		return nil, err
	}
	if self != l.Binary {
		bin, err := in.files.Read(self)
		if err != nil {
			return nil, fmt.Errorf("read own binary: %w", err)
		}
		c, err := in.files.Write(l.Binary, bin, 0o755)
		if err != nil {
			return nil, err
		}
		if c {
			changed = append(changed, l.Binary)
		}
	}

	unitsChanged := false
	for name, src := range map[string][]byte{BootUnit: a.BootUnit, AgentUnit: a.AgentUnit, DNSUnit: a.DNSUnit} {
		data, err := RenderUnit(name, src, l)
		if err != nil {
			return nil, err
		}
		path := l.UnitDir + "/" + name
		c, err := in.files.Write(path, data, 0o644)
		if err != nil {
			return nil, err
		}
		if c {
			unitsChanged = true
			changed = append(changed, path)
		}
	}
	if unitsChanged {
		if err := in.svc.DaemonReload(ctx); err != nil {
			return nil, err
		}
	}

	if !in.files.Exists(l.Config) {
		if _, err := in.files.Write(l.Config, a.Config, l.ConfigMode); err != nil {
			return nil, err
		}
		changed = append(changed, l.Config)
	}
	slices.Sort(changed)
	return changed, nil
}

// WarpResult says what the WARP step did.
type WarpResult struct {
	Migrated   bool
	Registered bool
	// Plus is set when a license was given: whether the account is WARP+.
	Plus bool
	// LicenseRefused says why a given license was not applied; the node
	// runs on the free account.
	LicenseRefused error
}

// InstallWarp takes over any hand-made WARP, registers the node unless it
// already has an account, applies a WARP+ license if one is given, and writes
// the exit config. The agent brings the exit up from it.
//
// The tool comes first: removing the hand-made WARP is irreversible, and a
// node that cannot download wgcf must keep it.
func (in *Installer) InstallWarp(ctx context.Context, l Layout, license string) (WarpResult, error) {
	var res WarpResult
	if err := in.warp.EnsureTool(ctx); err != nil {
		return res, err
	}
	migrated, err := in.Migrate(ctx, l.StateDir)
	if err != nil {
		return res, fmt.Errorf("migrate existing WARP: %w", err)
	}
	res.Migrated = migrated

	if !in.warp.Registered() {
		if err := in.warp.Register(ctx); err != nil {
			return res, err
		}
		res.Registered = true
	}
	if license != "" {
		plus, err := in.warp.ApplyLicense(ctx, license)
		switch {
		case errors.Is(err, ErrLicenseNotApplied):
			res.LicenseRefused = err
		case err != nil:
			return res, err
		}
		res.Plus = plus
	}
	return res, in.warp.WriteExitConf(ctx)
}

// ReissueWarp replaces the node's WARP account with a new registration — the
// exit's renew command, run by the agent when the exit has had no handshake
// for long (a revoked key, a deleted account), where no restart helps. The
// WARP+ license applied before goes to the new account. A failed registration
// puts the old account back.
func (in *Installer) ReissueWarp(ctx context.Context) (WarpResult, error) {
	res := WarpResult{}
	if err := in.warp.EnsureTool(ctx); err != nil {
		return res, err
	}
	license, err := in.warp.License()
	if err != nil {
		return res, err
	}
	restore, err := in.warp.Retire(ctx)
	if err != nil {
		return res, err
	}
	if err := in.warp.Register(ctx); err != nil {
		return res, errors.Join(fmt.Errorf("register a new WARP account: %w", err), restore())
	}
	res.Registered = true
	if license != "" {
		plus, err := in.warp.ApplyLicense(ctx, license)
		switch {
		case errors.Is(err, ErrLicenseNotApplied):
			res.LicenseRefused = err
		case err != nil:
			return res, err
		}
		res.Plus = plus
	}
	return res, in.warp.WriteExitConf(ctx)
}

// agentPackages are what the agent runs besides its own binary: nft applies
// the table. A minimal image can lack it — the agent then applies nothing and
// every exit stays dead.
var agentPackages = []string{"nftables"}

// EnsureTools installs the packages the agent needs, whatever -skip-base
// says: they are not the base's hardening but the agent's own tools.
func (in *Installer) EnsureTools(ctx context.Context) error {
	return in.pkgs.Install(ctx, agentPackages...)
}

// SetupResolver prepares the host for the vnm resolver — always, not only when
// the policy uses domain lists: the operator may add them later without
// installing again.
//
//   - Its user. The resolver is the vnm binary itself (dns ТЗ §4), so no
//     package is needed; the config of the dnsmasq it replaced is removed,
//     while a dnsmasq already running keeps serving until the agent restarts
//     the unit.
//   - Its port in the host firewall. DNS redirected from a downstream
//     interface is delivered locally, and a firewall that drops what it does
//     not allow — ufw on our nodes — would drop it: clients of a tunnel would
//     lose DNS altogether. The port stays shut on the uplink, where the vnm
//     table drops it and the resolver does not answer.
//
// The host's own resolver configuration is left alone. It returns the
// firewall the port was opened in, "" when none is active.
func (in *Installer) SetupResolver(ctx context.Context, l Layout, port uint16) (string, error) {
	if err := in.host.EnsureSystemUser(ctx, ResolverUser); err != nil {
		return "", fmt.Errorf("user %s: %w", ResolverUser, err)
	}
	if err := in.files.Remove(l.legacyResolverConf()); err != nil {
		return "", err
	}
	if port == 0 {
		return "", nil
	}
	fw, err := in.host.AllowPort(ctx, port, "vnm resolver: DNS redirected from downstream")
	if err != nil {
		return fw, fmt.Errorf("open port %d in %s: %w", port, fw, err)
	}
	return fw, nil
}

// AllowExitForwarding lets tunnel clients' traffic out through each exit's
// interface in the host firewall: firewalld forwards only to interfaces of a
// zone and rejects the rest, which clients see as "unreachable" for every
// destination the policy sends through the exit. It returns the firewall
// changed, "" when none restricts forwarding.
func (in *Installer) AllowExitForwarding(ctx context.Context, ifaces []string) (string, error) {
	var fw string
	for _, iface := range ifaces {
		got, err := in.host.AllowForwardTo(ctx, iface)
		if err != nil {
			return got, fmt.Errorf("forward to %s in %s: %w", iface, got, err)
		}
		fw = got
	}
	return fw, nil
}

// Start enables the units and starts the agent — restarting it when it was
// already running, so a new binary takes over.
func (in *Installer) Start(ctx context.Context) error {
	wasActive := in.svc.Active(ctx, AgentUnit)
	if err := in.svc.EnableNow(ctx, BootUnit, AgentUnit, DNSUnit); err != nil {
		return err
	}
	if wasActive {
		return in.svc.Restart(ctx, AgentUnit)
	}
	return nil
}
