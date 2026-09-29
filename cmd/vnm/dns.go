package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"os"

	"github.com/lib4u/vnm/internal/app"
	"github.com/lib4u/vnm/internal/infrastructure/dnsd"
	"github.com/lib4u/vnm/internal/infrastructure/nftables"
	"github.com/lib4u/vnm/internal/infrastructure/sdnotify"
)

// runDNS runs `vnm dns serve`: the resolver vnm-dns.service runs, as its own
// user, on the config the agent writes (docs/vpn-node-manager-dns-tz.md).
func runDNS(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] != "serve" {
		return errors.New("usage: vnm dns serve [-config PATH]")
	}
	fs := flag.NewFlagSet("dns serve", flag.ContinueOnError)
	conf := fs.String("config", app.DefaultPaths.Layout().ResolverConf(), "the resolver config the agent writes")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil)).With("service", "vnm-dns", "version", version)
	cfg, err := dnsd.Load(*conf)
	if err != nil {
		return err
	}
	srv := dnsd.New(dnsd.Options{Config: cfg, Filler: &nftables.ResolverSets{}, Log: log})
	log.Info("resolver starting", "port", cfg.Port, "lists", len(cfg.Sets))
	return srv.Serve(ctx, func() {
		if err := sdnotify.Ready(); err != nil {
			log.Warn("notify systemd", "error", err)
		}
	})
}
