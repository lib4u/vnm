// Package resolver keeps the vnm resolver serving the applied state
// (docs/vpn-node-manager-dns-tz.md): it writes the config `vnm dns serve`
// reads, restarts vnm-dns.service when that changes, and probes it.
package resolver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"os/user"
	"strconv"

	"github.com/lib4u/vnm/internal/domain/netstate"
	"github.com/lib4u/vnm/internal/infrastructure/atomicfile"
	"github.com/lib4u/vnm/internal/infrastructure/dnsd"
	"github.com/lib4u/vnm/internal/infrastructure/nftables"
	"github.com/lib4u/vnm/internal/infrastructure/runner"
	"github.com/lib4u/vnm/internal/usecase/install"
)

// Resolver writes the resolver's config and keeps its unit running.
type Resolver struct {
	conf string
	run  runner.Runner
}

// New returns a Resolver writing its config to conf.
func New(conf string, run runner.Runner) *Resolver {
	return &Resolver{conf: conf, run: run}
}

// Apply makes the resolver serve the state's domain sets: a changed config is
// written and the unit restarted; no domain sets stops the unit.
func (r *Resolver) Apply(ctx context.Context, s netstate.State) error {
	if !s.DNS.Enabled() {
		if _, err := os.Stat(r.conf); errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if _, err := r.systemctl(ctx, "stop", install.DNSUnit); err != nil {
			return err
		}
		return os.Remove(r.conf)
	}

	data, err := Config(s.DNS, s.Classify.Uplinks).Encode()
	if err != nil {
		return err
	}
	if old, err := os.ReadFile(r.conf); err == nil && bytes.Equal(old, data) {
		// Unchanged; make sure it runs (the condition on the config's
		// existence may have kept it from starting at boot).
		_, err := r.systemctl(ctx, "start", install.DNSUnit)
		return err
	}
	if err := atomicfile.WriteFile(r.conf, data, 0o644); err != nil {
		return err
	}
	// A restart, not a reload: the unit may still run the resolver of an
	// earlier release, which reads no config of this kind.
	_, err = r.systemctl(ctx, "restart", install.DNSUnit)
	return err
}

// UID returns the uid of the resolver's user.
func (r *Resolver) UID() (uint32, error) {
	u, err := user.Lookup(install.ResolverUser)
	if err != nil {
		return 0, err
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("user %s: uid %q: %w", install.ResolverUser, u.Uid, err)
	}
	return uint32(uid), nil
}

// Up reports whether the resolver answers on the port.
func (r *Resolver) Up(ctx context.Context, port uint16) bool {
	return Answers(ctx, onLoopback(port))
}

// UDPDropped returns how many UDP queries the resolver on the port dropped
// over its in-flight limit since it started.
func (r *Resolver) UDPDropped(ctx context.Context, port uint16) (uint64, error) {
	return UDPDropped(ctx, onLoopback(port))
}

// onLoopback is where the agent itself asks the resolver: 127.0.0.2, not
// 127.0.0.1. The host's own DNS (xray asking 127.0.0.53:53) is redirected to
// 127.0.0.1:<port>, and every such query holds the reply tuple
// 127.0.0.1:<port> <-> 127.0.0.1:<its port> in conntrack for up to two minutes.
// On a busy node that is thousands of local ports, and a probe sent from one of
// them to 127.0.0.1 collides at conntrack confirm: the kernel drops it and the
// send fails with EPERM. Seen on NL-2 19.11.2026: 35-45 % of probes lost, the
// resolver taken for dead every few minutes and the node flapping into
// failover. Replies from 127.0.0.2 never match a redirected entry.
// The resolver listens on the wildcard address, so it answers there too.
func onLoopback(port uint16) netip.AddrPort {
	return netip.AddrPortFrom(probeAddr, port)
}

var probeAddr = netip.AddrFrom4([4]byte{127, 0, 0, 2})

func (r *Resolver) systemctl(ctx context.Context, args ...string) (string, error) {
	out, err := r.run.Run(ctx, runner.Command{Name: "systemctl", Args: args})
	if err != nil {
		return out, fmt.Errorf("resolver: %w", err)
	}
	return out, nil
}

// Config is the resolver's config for the state: the sets under their names
// in the kernel.
func Config(d netstate.DNSState, uplinks []string) dnsd.Config {
	c := dnsd.Config{Port: d.Port, Upstreams: d.Upstreams, Uplinks: uplinks, Sets: []dnsd.DomainSet{}}
	for _, s := range d.Sets {
		c.Sets = append(c.Sets, dnsd.DomainSet{
			Set4: nftables.SetName(s.Set4), Set6: nftables.SetName(s.Set6), Domains: s.Domains, NoAAAA: s.NoAAAA,
		})
	}
	return c
}
