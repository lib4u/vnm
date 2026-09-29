package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"

	vnm "github.com/lib4u/vnm"
	"github.com/lib4u/vnm/internal/app"
	"github.com/lib4u/vnm/internal/domain/policy"
	"github.com/lib4u/vnm/internal/infrastructure/configfile"
	"github.com/lib4u/vnm/internal/usecase/agent"
	"github.com/lib4u/vnm/internal/usecase/exits"
	"github.com/lib4u/vnm/internal/usecase/install"
)

// warpExit is the exit the installer registers with WARP.
const warpExit = "warp"

// healthWait is how long `vnm install` waits for the exit to prove itself.
const healthWait = 2 * time.Minute

// installFlags are the flags of the installing commands.
type installFlags struct {
	fs       *flag.FlagSet
	paths    *app.Paths
	license  string
	skipBase bool
	trust    string
}

func newInstallFlags(name string) *installFlags {
	fs, paths := pathFlags(name)
	f := &installFlags{fs: fs, paths: paths}
	fs.StringVar(&f.license, "license", "", "WARP+ license key")
	fs.BoolVar(&f.skipBase, "skip-base", false, "leave SSH, fail2ban, sysctl and swap alone")
	fs.StringVar(&f.trust, "trust", "", "comma-separated ranges fail2ban never bans, besides the policy's exempt ones")
	return f
}

// policyForInstall reads the node's policy, or the shipped template when the
// node has none yet: it names the WARP exit's config path and the exempt
// ranges.
func policyForInstall(path string) (policy.Config, error) {
	if _, err := os.Stat(path); err == nil {
		return configfile.Load(path)
	}
	return configfile.Parse(vnm.DefaultConfig)
}

// installer wires the installer for the commands that register the WARP exit:
// they need the policy and its exit.
func (f *installFlags) installer() (*install.Installer, policy.Config, error) {
	cfg, err := policyForInstall(f.paths.Config)
	if err != nil {
		return nil, cfg, err
	}
	exit, ok := cfg.Exit(warpExit)
	if !ok {
		return nil, cfg, fmt.Errorf("the policy has no exit named %q to register with WARP", warpExit)
	}
	return f.paths.NewInstaller(exit.Conf), cfg, nil
}

// baseInstaller wires the installer for `vnm base`: it does not read the
// policy, since a broken one must not keep `vnm base confirm` from keeping
// SSH within its window.
func (f *installFlags) baseInstaller() *install.Installer {
	return f.paths.NewBaseInstaller()
}

// policyExempt is the policy's exempt ranges, best effort: without a readable
// policy fail2ban trusts only the -trust ranges.
func (f *installFlags) policyExempt() []netip.Prefix {
	cfg, err := policyForInstall(f.paths.Config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "base: WARN the policy is unreadable, fail2ban trusts only -trust ranges: %v\n", err)
		return nil
	}
	return cfg.Exempt
}

func (f *installFlags) trusted(exempt []netip.Prefix) ([]netip.Prefix, error) {
	trusted := slices.Clone(exempt)
	for raw := range strings.SplitSeq(f.trust, ",") {
		if raw = strings.TrimSpace(raw); raw == "" {
			continue
		}
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("-trust %q: %w", raw, err)
		}
		trusted = append(trusted, p)
	}
	return trusted, nil
}

// runInstall sets the node up end to end.
func runInstall(ctx context.Context, args []string) error {
	f := newInstallFlags("install")
	if err := f.fs.Parse(args); err != nil {
		return err
	}
	in, cfg, err := f.installer()
	if err != nil {
		return err
	}
	if err := in.Preflight(); err != nil {
		return err
	}
	if !f.skipBase {
		if err := applyBase(ctx, in, f, cfg.Exempt); err != nil {
			return err
		}
	}

	if err := in.EnsureTools(ctx); err != nil {
		return fmt.Errorf("tools: %w", err)
	}
	changed, err := in.PlaceFiles(ctx, f.paths.Layout(), install.Assets{
		Config: vnm.DefaultConfig, BootUnit: vnm.BootUnit, AgentUnit: vnm.AgentUnit, DNSUnit: vnm.DNSUnit,
	})
	if err != nil {
		return fmt.Errorf("files: %w", err)
	}
	for _, path := range changed {
		fmt.Println("installed", path)
	}
	if err := installWarp(ctx, in, f); err != nil {
		return err
	}
	// The policy on disk now — the operator's, or the template just placed.
	if cfg, err = configfile.Load(f.paths.Config); err != nil {
		return err
	}
	fw, err := in.SetupResolver(ctx, f.paths.Layout(), cfg.DNS.Port)
	if err != nil {
		return fmt.Errorf("resolver: %w", err)
	}
	if fw != "" {
		fmt.Printf("resolver: port %d allowed in %s (the uplink stays shut by the vnm table)\n", cfg.DNS.Port, fw)
	}
	var ifaces []string
	for _, e := range cfg.Exits {
		ifaces = append(ifaces, e.Iface)
	}
	if fw, err := in.AllowExitForwarding(ctx, ifaces); err != nil {
		return fmt.Errorf("exits: %w", err)
	} else if fw != "" {
		fmt.Printf("exits: forwarding to %v allowed in %s\n", ifaces, fw)
	}
	started := time.Now()
	if err := in.Start(ctx); err != nil {
		return fmt.Errorf("start: %w", err)
	}
	fmt.Println("agent started; waiting for the exit to prove itself …")
	return waitHealthy(ctx, *f.paths, started)
}

func runBase(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: vnm base apply|confirm")
	}
	f := newInstallFlags("base " + args[0])
	if err := f.fs.Parse(args[1:]); err != nil {
		return err
	}
	in := f.baseInstaller()
	switch args[0] {
	case "apply":
		if err := in.Preflight(); err != nil {
			return err
		}
		return applyBase(ctx, in, f, f.policyExempt())
	case "confirm":
		if err := in.ConfirmBase(ctx, f.paths.Layout()); err != nil {
			return err
		}
		fmt.Println("SSH hardening kept")
		return nil
	default:
		return fmt.Errorf("unknown base command %q", args[0])
	}
}

func applyBase(ctx context.Context, in *install.Installer, f *installFlags, exempt []netip.Prefix) error {
	trusted, err := f.trusted(exempt)
	if err != nil {
		return err
	}
	res, err := in.Base(ctx, f.paths.Layout(), trusted)
	for _, c := range res.Changed {
		fmt.Println("base:", c)
	}
	if err != nil {
		return fmt.Errorf("base: %w", err)
	}
	if res.ConfirmSSH {
		fmt.Printf("SSH: password login is off and rolls back %v after it was applied unless you run\n", install.SSHConfirmWindow)
		fmt.Println("     `vnm base confirm` from a NEW ssh session.")
	}
	return nil
}

func runWarp(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: vnm warp install [-license KEY] | vnm warp plus KEY | vnm warp reissue")
	}
	f := newInstallFlags("warp " + args[0])
	if err := f.fs.Parse(args[1:]); err != nil {
		return err
	}
	in, _, err := f.installer()
	if err != nil {
		return err
	}
	switch args[0] {
	case "install":
		return installWarp(ctx, in, f)
	case "plus":
		if f.fs.NArg() != 1 {
			return errors.New("usage: vnm warp plus KEY")
		}
		f.license = f.fs.Arg(0)
		return installWarp(ctx, in, f)
	case "reissue":
		res, err := in.ReissueWarp(ctx)
		if err != nil {
			return fmt.Errorf("warp reissue: %w", err)
		}
		fmt.Println("warp: a new account is registered and the exit config rewritten")
		if res.LicenseRefused != nil {
			fmt.Println("warp: WARN the WARP+ license was not applied to the new account:", res.LicenseRefused)
		} else if res.Plus {
			fmt.Println("warp: WARP+ active")
		}
		return nil
	default:
		return fmt.Errorf("unknown warp command %q", args[0])
	}
}

func installWarp(ctx context.Context, in *install.Installer, f *installFlags) error {
	res, err := in.InstallWarp(ctx, f.paths.Layout(), f.license)
	if err != nil {
		return fmt.Errorf("warp: %w", err)
	}
	if res.Migrated {
		fmt.Println("warp: the hand-made WARP was taken over and removed (backup in", f.paths.StateDir+"/migration)")
	}
	if res.Registered {
		fmt.Println("warp: registered")
	}
	switch {
	case f.license == "":
	case res.LicenseRefused != nil:
		fmt.Printf("warp: WARN %v; the free account keeps working\n", res.LicenseRefused)
	case res.Plus:
		fmt.Println("warp: WARP+ active")
	default:
		fmt.Println("warp: WARN the account did not become WARP+; the free account keeps working")
	}
	return nil
}

// waitHealthy watches the agent's status until a pass made after since — by
// the agent just (re)started, not the one before it — reports the WARP exit
// healthy.
func waitHealthy(ctx context.Context, paths app.Paths, since time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, healthWait)
	defer cancel()
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	status := paths.Status()
	for {
		if s, err := status.Read(); err == nil && s.LastReconcile.After(since) && warpHealthy(s) {
			fmt.Println("exit healthy — vnm is running")
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("the exit did not become healthy within %v; see `vnm status` and `journalctl -u vnm-agent`", healthWait)
		case <-tick.C:
		}
	}
}

func warpHealthy(s agent.Snapshot) bool {
	return slices.ContainsFunc(s.Exits, func(e exits.Status) bool { return e.Name == warpExit && e.Healthy })
}
