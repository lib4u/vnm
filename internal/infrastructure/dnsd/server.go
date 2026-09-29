package dnsd

import (
	"context"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Filler puts addresses into the sets.
type Filler interface {
	// Add adds every addition in one transaction: it returns once the kernel
	// holds them all, or fails with none of them relied on.
	Add(ctx context.Context, adds []Addition) error
}

// Limits of what the resolver takes on at once (dns ТЗ §3.1).
const (
	maxUDPInFlight = 1024
	maxTCPConns    = 256
	tcpIdle        = 10 * time.Second
)

// Server is the resolver.
type Server struct {
	port    uint16
	idx     *index
	fwd     *forwarder
	fill    Filler
	uplinks *uplinks
	log     *rateLog
	udp     chan struct{}
	tcp     chan struct{}
}

// Options are the resolver's collaborators; a nil Exchanger or Interfaces is
// the real network.
type Options struct {
	Config     Config
	Filler     Filler
	Exchanger  Exchanger
	Interfaces Interfaces
	Log        *slog.Logger
}

// New returns a resolver serving the config.
func New(o Options) *Server {
	ex := o.Exchanger
	if ex == nil {
		ex = clientExchanger{}
	}
	ifs := o.Interfaces
	if ifs == nil {
		ifs = systemInterfaces
	}
	return &Server{
		port:    o.Config.Port,
		idx:     newIndex(o.Config.Sets),
		fwd:     &forwarder{upstreams: o.Config.Upstreams, ex: ex},
		fill:    o.Filler,
		uplinks: newUplinks(o.Config.Uplinks, ifs),
		log:     &rateLog{log: o.Log, last: map[string]time.Time{}},
		udp:     make(chan struct{}, maxUDPInFlight),
		tcp:     make(chan struct{}, maxTCPConns),
	}
}

// answer returns the packed reply to a packed query, or nil when nothing is to
// be sent back.
func (s *Server) answer(ctx context.Context, req []byte, tcp bool) []byte {
	q := new(dns.Msg)
	if err := q.Unpack(req); err != nil || q.Response {
		return nil
	}
	r := s.reply(ctx, q, tcp)
	if !tcp {
		r.Truncate(clientUDPSize(q))
	}
	r.Compress = true
	out, err := r.Pack()
	if err != nil {
		s.log.warn("pack", "cannot pack a reply", "err", err)
		out, _ = rcode(q, dns.RcodeServerFailure).Pack()
	}
	return out
}

func (s *Server) reply(ctx context.Context, q *dns.Msg, tcp bool) *dns.Msg {
	switch {
	case q.Opcode != dns.OpcodeQuery:
		return rcode(q, dns.RcodeNotImplemented)
	case len(q.Question) != 1:
		return rcode(q, dns.RcodeFormatError)
	case q.Question[0].Qclass == dns.ClassCHAOS:
		return chaos(q)
	}
	r, err := s.fwd.forward(ctx, q, tcp)
	if err != nil {
		s.log.warn("upstream", "no upstream answered", "err", err)
		return rcode(q, dns.RcodeServerFailure)
	}
	// The addresses of a listed domain reach its sets before the client can
	// connect to them; an address that did not make it is never handed out,
	// or the connection would leave through the node's own address (I-1).
	hit := s.idx.hits(r)
	s.idx.stripIPv6(r, hit)
	if adds := s.idx.additions(r, hit); len(adds) > 0 {
		if err := s.fill.Add(ctx, adds); err != nil {
			s.log.warn("sets", "cannot add addresses to the sets; the answer is refused", "err", err)
			return rcode(q, dns.RcodeServerFailure)
		}
	}
	return r
}

// chaos answers "version.bind" TXT itself: the agent's liveness probe, which
// must not depend on the upstreams. Any other CHAOS query is refused.
func chaos(q *dns.Msg) *dns.Msg {
	qq := q.Question[0]
	if qq.Qtype != dns.TypeTXT || !strings.EqualFold(qq.Name, "version.bind.") {
		return rcode(q, dns.RcodeRefused)
	}
	r := rcode(q, dns.RcodeSuccess)
	r.Authoritative = true
	r.Answer = []dns.RR{&dns.TXT{
		Hdr: dns.RR_Header{Name: qq.Name, Rrtype: dns.TypeTXT, Class: dns.ClassCHAOS},
		Txt: []string{"vnm"},
	}}
	return r
}

func rcode(q *dns.Msg, code int) *dns.Msg {
	r := new(dns.Msg)
	r.SetRcode(q, code)
	r.RecursionAvailable = true
	return r
}

// clientUDPSize is the largest UDP answer the client takes.
func clientUDPSize(q *dns.Msg) int {
	if opt := q.IsEdns0(); opt != nil {
		return max(dns.MinMsgSize, int(opt.UDPSize()))
	}
	return dns.MinMsgSize
}

// Interfaces looks an interface up: its index and addresses.
type Interfaces func(name string) (index int, addrs []netip.Addr, err error)

// uplinks are the interfaces nothing may be answered on (dns ТЗ §3.1). They
// are looked up again every refreshEvery: an interface can be recreated.
type uplinks struct {
	names  []string
	lookup Interfaces

	mu      sync.RWMutex
	indexes map[int]bool
	addrs   map[netip.Addr]bool
}

const refreshEvery = 30 * time.Second

func newUplinks(names []string, lookup Interfaces) *uplinks {
	u := &uplinks{names: names, lookup: lookup}
	u.refresh()
	return u
}

func (u *uplinks) refresh() {
	indexes, addrs := map[int]bool{}, map[netip.Addr]bool{}
	for _, name := range u.names {
		i, as, err := u.lookup(name)
		if err != nil {
			continue // gone for now; the kernel's guard still drops it
		}
		indexes[i] = true
		for _, a := range as {
			addrs[a.Unmap()] = true
		}
	}
	u.mu.Lock()
	u.indexes, u.addrs = indexes, addrs
	u.mu.Unlock()
}

func (u *uplinks) hasIndex(i int) bool {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.indexes[i]
}

func (u *uplinks) hasAddr(a netip.Addr) bool {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.addrs[a.Unmap()]
}

// rateLog writes a warning of each kind at most once per rateEvery: a dead
// upstream must not flood the journal with one line per query.
type rateLog struct {
	log  *slog.Logger
	mu   sync.Mutex
	last map[string]time.Time
}

const rateEvery = 10 * time.Second

func (r *rateLog) warn(kind, msg string, args ...any) {
	if r.log == nil {
		return
	}
	r.mu.Lock()
	now := time.Now()
	if now.Sub(r.last[kind]) < rateEvery {
		r.mu.Unlock()
		return
	}
	r.last[kind] = now
	r.mu.Unlock()
	r.log.Warn(msg, args...)
}
