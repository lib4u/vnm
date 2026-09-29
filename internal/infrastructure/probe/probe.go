// Package probe checks that traffic gets through an exit (ТЗ §4).
//
// The probe socket carries the exit's mark, so the kernel routes it into the
// exit's table — the same way marked traffic of the node goes. The probe host
// is resolved ahead of time through the normal resolver and cached: the check
// itself must not depend on DNS, or a resolver outage would be read as a dead
// exit.
package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"github.com/lib4u/vnm/internal/domain/netstate"
	"github.com/lib4u/vnm/internal/domain/policy"
	"github.com/lib4u/vnm/internal/usecase/exits"
)

const (
	// timeout bounds one probe (ТЗ §4).
	timeout = 5 * time.Second
	// resolveTTL is how long a resolved probe address is reused.
	resolveTTL = time.Hour
	// resolveTimeout bounds a resolution of the probe host.
	resolveTimeout = 10 * time.Second
	// maxBody caps what is read of the probe answer.
	maxBody = 64 << 10
)

// ErrUnexpected means the exit answered, but not with the expected body — for
// example a Cloudflare error page without "warp=on": traffic may be leaving
// some other way, so the exit is not confirmed.
var ErrUnexpected = errors.New("probe answer does not match")

// HTTP probes exits over HTTPS.
type HTTP struct {
	resolver *net.Resolver
	roots    *x509.CertPool
	now      func() time.Time

	mu    sync.Mutex
	cache map[string]resolved
}

type resolved struct {
	addr  netip.Addr
	until time.Time
}

var _ exits.Prober = (*HTTP)(nil)

// Option configures an HTTP prober.
type Option func(*HTTP)

// WithRootCAs trusts roots instead of the system pool.
func WithRootCAs(roots *x509.CertPool) Option {
	return func(p *HTTP) { p.roots = roots }
}

// New returns an HTTP prober.
func New(opts ...Option) *HTTP {
	p := &HTTP{resolver: net.DefaultResolver, now: time.Now, cache: map[string]resolved{}}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// Probe fetches the exit's probe URL through the exit and matches the body.
// The probe host is resolved outside the probe's own time budget: a slow
// resolver must not eat it, and a failed resolution with nothing cached is
// ErrProbeUnknown — it says nothing about the exit.
func (p *HTTP) Probe(ctx context.Context, e policy.Exit) error {
	u := e.Health.URL
	host := u.Hostname()
	addr, err := p.resolve(ctx, host)
	if err != nil {
		return fmt.Errorf("%w: %w", exits.ErrProbeUnknown, err)
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	port := u.Port()
	if port == "" {
		port = "443"
	}
	target := net.JoinHostPort(addr.String(), port)
	// The bypass bit keeps the probe out of the classification: a dead exit's
	// reject must not refuse the very probe that could bring it back.
	dialer := &net.Dialer{Control: markSocket(netstate.BypassToExit(e.Slot))}
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, target)
			},
			TLSClientConfig:   &tls.Config{ServerName: host, RootCAs: p.roots, MinVersion: tls.VersionTLS12},
			DisableKeepAlives: true,
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return fmt.Errorf("probe request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("probe %s through %s: %w", host, e.Iface, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return fmt.Errorf("read probe answer: %w", err)
	}
	if !e.Health.Expect.Match(body) {
		return fmt.Errorf("%w: status %s", ErrUnexpected, resp.Status)
	}
	return nil
}

// resolve returns a cached address of host, resolving it through the system
// resolver when the cache is empty or old. An IP literal is used as is.
func (p *HTTP) resolve(ctx context.Context, host string) (netip.Addr, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr, nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if r, ok := p.cache[host]; ok && p.now().Before(r.until) {
		return r.addr, nil
	}
	ctx, cancel := context.WithTimeout(ctx, resolveTimeout)
	defer cancel()
	addrs, err := p.resolver.LookupNetIP(ctx, "ip4", host)
	if err != nil || len(addrs) == 0 {
		if r, ok := p.cache[host]; ok {
			// A stale address beats none: the resolver being down says nothing
			// about the exit.
			return r.addr, nil
		}
		return netip.Addr{}, fmt.Errorf("resolve probe host %s: %w", host, err)
	}
	p.cache[host] = resolved{addr: addrs[0], until: p.now().Add(resolveTTL)}
	return addrs[0], nil
}

// markSocket sets SO_MARK before connect, so the connection is routed by the
// mark from its first packet. Marking later, in netfilter, would come after the
// source address was chosen and the probe would fail for the wrong reason.
func markSocket(mark uint32) func(network, address string, c syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var sockErr error
		err := c.Control(func(fd uintptr) {
			sockErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, int(mark))
		})
		if err != nil {
			return err
		}
		if sockErr != nil {
			return fmt.Errorf("set SO_MARK %#x: %w", mark, sockErr)
		}
		return nil
	}
}
