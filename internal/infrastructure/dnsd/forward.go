package dnsd

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// Forwarding limits (dns ТЗ §3.2).
const (
	attemptTimeout = 2 * time.Second
	queryBudget    = 5 * time.Second
)

// Exchanger sends one query to one upstream over "udp" or "tcp".
type Exchanger interface {
	Exchange(ctx context.Context, m *dns.Msg, network string, upstream netip.AddrPort) (*dns.Msg, error)
}

// clientExchanger is the real network.
type clientExchanger struct{}

func (clientExchanger) Exchange(ctx context.Context, m *dns.Msg, network string, upstream netip.AddrPort) (*dns.Msg, error) {
	c := dns.Client{Net: network, Timeout: attemptTimeout, UDPSize: dns.MaxMsgSize}
	r, _, err := c.ExchangeContext(ctx, m, upstream.String())
	return r, err
}

// forwarder asks the upstreams in order, the one that answered last first.
type forwarder struct {
	upstreams []netip.AddrPort
	ex        Exchanger
	last      atomic.Int32
}

// errNoUpstream means no upstream gave an answer.
var errNoUpstream = errors.New("no upstream answered")

// forward returns an upstream's answer to q, carrying q's ID. A UDP answer
// cut short is asked again over TCP of the same upstream; SERVFAIL and REFUSED
// move on to the next upstream, and are returned only when no upstream did
// better.
func (f *forwarder) forward(ctx context.Context, q *dns.Msg, tcp bool) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(ctx, queryBudget)
	defer cancel()

	out := q.Copy()
	out.Id = dns.Id()
	network := "udp"
	if tcp {
		network = "tcp"
	}
	var fallback *dns.Msg
	var errs []error
	first := int(f.last.Load())
	for n := range f.upstreams {
		i := (first + n) % len(f.upstreams)
		up := f.upstreams[i]
		r, err := f.ex.Exchange(ctx, out, network, up)
		if err == nil && r.Truncated && network == "udp" {
			r, err = f.ex.Exchange(ctx, out, "tcp", up)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", up, err))
			if ctx.Err() != nil {
				break
			}
			continue
		}
		r.Id = q.Id
		if r.Rcode == dns.RcodeServerFailure || r.Rcode == dns.RcodeRefused {
			fallback = r
			continue
		}
		f.last.Store(int32(i))
		return r, nil
	}
	if fallback != nil {
		return fallback, nil
	}
	return nil, fmt.Errorf("%w: %w", errNoUpstream, errors.Join(errs...))
}
