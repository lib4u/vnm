// Command vnm is the vpn-node-manager (docs/vpn-node-manager-tz.md).
//
//	vnm install [-license KEY] [-skip-base] [-trust CIDR,…]
//	                          set the node up: base, WARP, files, units
//	vnm base apply [-trust …] SSH by key, fail2ban, sysctl, swap
//	vnm base confirm          keep the SSH change (run from a new session)
//	vnm warp install [-license KEY]
//	vnm warp plus KEY         upgrade the registration to WARP+
//	vnm egress observe|enforce|off [-allow-leak] [-auto-rollback 5m]
//	                          switch the policy's mode; leaving enforce needs -allow-leak
//	vnm guard observe|enforce|off [-auto-rollback 5m]
//	                          switch the inbound guard's mode
//	vnm egress|guard confirm|rollback
//	                          keep or undo a provisional switch
//	vnm status                what the agent saw on its last pass
//	vnm test IP|DOMAIN        what the node does with a destination
//	vnm doctor                check the node end to end
//	vnm lists update          download the remote lists now
//	vnm agent                 the control loop (vnm-agent.service)
//	vnm boot                  restore the last good state (vnm-boot.service)
//	vnm dns serve             the resolver behind the domain lists (vnm-dns.service)
//	vnm version
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/lib4u/vnm/internal/app"
	"github.com/lib4u/vnm/internal/infrastructure/sdnotify"
)

// version is stamped at build time with -ldflags "-X main.version=…".
var version = "dev"

const usage = "usage: vnm install|base|warp|egress|guard|lists|status|test|doctor|agent|boot|dns|version … (see the package doc)"

func main() {
	err := run(os.Args[1:])
	switch {
	case errors.Is(err, flag.ErrHelp):
		// The flag set already printed the help that was asked for.
	case err != nil:
		fmt.Fprintf(os.Stderr, "vnm: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New(usage)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cmd, args := args[0], args[1:]
	switch cmd {
	case "agent", "boot", "status", "test", "doctor", "version":
		fs, paths := pathFlags(cmd)
		if err := fs.Parse(args); err != nil {
			return err
		}
		switch cmd {
		case "agent":
			return runAgent(ctx, *paths)
		case "boot":
			return runBoot(ctx, *paths)
		case "status":
			return runStatus(*paths)
		case "doctor":
			return runDoctor(ctx, *paths)
		case "test":
			if fs.NArg() != 1 {
				return errors.New("usage: vnm test IP|DOMAIN")
			}
			return runTest(ctx, *paths, fs.Arg(0))
		default:
			fmt.Println(version)
			return nil
		}
	case "install":
		return runInstall(ctx, args)
	case "base":
		return runBase(ctx, args)
	case "warp":
		return runWarp(ctx, args)
	case "egress", "guard":
		return runSwitch(ctx, cmd, args)
	case "dns":
		return runDNS(ctx, args)
	case "lists":
		if len(args) == 0 || args[0] != "update" {
			return errors.New("usage: vnm lists update")
		}
		fs, paths := pathFlags("lists update")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		return runListsUpdate(ctx, *paths)
	default:
		return fmt.Errorf("unknown command %q; %s", cmd, usage)
	}
}

// pathFlags is a flag set with the path overrides every command accepts.
func pathFlags(name string) (*flag.FlagSet, *app.Paths) {
	paths := app.DefaultPaths
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	paths.Bind(fs)
	return fs, &paths
}

func runAgent(ctx context.Context, paths app.Paths) error {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil)).With("service", "vnm-agent", "version", version)
	agent, err := app.NewAgent(paths, log)
	if err != nil {
		return err
	}
	defer agent.Close()

	// Ready means "the kernel holds a planned state or the last good one",
	// which the boot unit already guaranteed; the first pass follows at once.
	if err := sdnotify.Ready(); err != nil {
		log.Warn("notify systemd", "error", err)
	}
	log.Info("agent started")
	return agent.Run(ctx)
}

// runBoot re-applies the last good state from disk alone: no network, no
// downloads, no planning. A node that crashed comes back with its policy in
// place before any service can pass traffic (ТЗ §7.2).
func runBoot(ctx context.Context, paths app.Paths) error {
	release, err := paths.Locker().Lock(ctx)
	if err != nil {
		return err
	}
	defer release()
	applier, _ := paths.Applier()
	return applier.Restore(ctx)
}
