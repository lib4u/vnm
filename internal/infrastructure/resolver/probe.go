package resolver

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"time"

	"github.com/miekg/dns"

	"github.com/lib4u/vnm/internal/infrastructure/dnsd"
)

// A resolver on loopback answers in microseconds, so an attempt unanswered for
// attemptTimeout was lost, not slow. A lost datagram must not make a live
// resolver look dead, so a probe gives up only after probeAttempts attempts in
// a row: one pass decides, with no state carried between passes, and a
// resolver that is really gone refuses each attempt at once.
const probeAttempts = 3

var attemptTimeout = time.Second

// Answers reports whether a DNS server answers at addr over UDP. It asks
// "version.bind" CH TXT, which the vnm resolver answers itself, without its
// upstreams and without waiting for a free in-flight slot: an answer proves it
// serves on the port and nothing more.
func Answers(ctx context.Context, addr netip.AddrPort) bool {
	_, err := askChaos(ctx, addr, dnsd.VersionName)
	return err == nil
}

// UDPDropped returns how many UDP queries the vnm resolver at addr dropped
// over its in-flight limit since it started.
func UDPDropped(ctx context.Context, addr netip.AddrPort) (uint64, error) {
	r, err := askChaos(ctx, addr, dnsd.UDPDroppedName)
	if err != nil {
		return 0, err
	}
	if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1 {
		return 0, fmt.Errorf("%s: rcode %s, %d answers", dnsd.UDPDroppedName, dns.RcodeToString[r.Rcode], len(r.Answer))
	}
	txt, ok := r.Answer[0].(*dns.TXT)
	if !ok || len(txt.Txt) != 1 {
		return 0, fmt.Errorf("%s: not a single TXT string: %v", dnsd.UDPDroppedName, r.Answer[0])
	}
	return strconv.ParseUint(txt.Txt[0], 10, 64)
}

// askChaos asks a CHAOS TXT question, up to probeAttempts times.
func askChaos(ctx context.Context, addr netip.AddrPort, name string) (*dns.Msg, error) {
	q := new(dns.Msg)
	q.SetQuestion(name, dns.TypeTXT)
	q.Question[0].Qclass = dns.ClassCHAOS
	c := dns.Client{Net: "udp", Timeout: attemptTimeout}
	var errs []error
	for range probeAttempts {
		r, _, err := c.ExchangeContext(ctx, q, addr.String())
		if err == nil {
			return r, nil
		}
		errs = append(errs, err)
		if ctx.Err() != nil {
			break
		}
	}
	return nil, errors.Join(errs...)
}
