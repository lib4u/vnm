package dnsd

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// upstreams answers from a zone, and records what it was asked.
type upstreams struct {
	mu    sync.Mutex
	asked []string // "network upstream"
	// answer builds the reply of an upstream; nil fails the exchange.
	answer func(up netip.AddrPort, network string, q *dns.Msg) *dns.Msg
}

func (u *upstreams) Exchange(_ context.Context, m *dns.Msg, network string, up netip.AddrPort) (*dns.Msg, error) {
	u.mu.Lock()
	u.asked = append(u.asked, network+" "+up.String())
	u.mu.Unlock()
	r := u.answer(up, network, m)
	if r == nil {
		return nil, errors.New("timeout")
	}
	r.Id = m.Id
	return r, nil
}

// zone answers every question from records given as text.
func zone(records ...string) func(netip.AddrPort, string, *dns.Msg) *dns.Msg {
	return func(_ netip.AddrPort, _ string, q *dns.Msg) *dns.Msg {
		r := new(dns.Msg)
		r.SetReply(q)
		for _, rec := range records {
			rr, err := dns.NewRR(rec)
			if err != nil {
				panic(err)
			}
			r.Answer = append(r.Answer, rr)
		}
		return r
	}
}

// sets records what reached the kernel, in order.
type sets struct {
	mu   sync.Mutex
	adds []Addition
	err  error
}

func (s *sets) Add(_ context.Context, adds []Addition) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.adds = append(s.adds, adds...)
	return nil
}

func (s *sets) got() map[string][]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string][]string{}
	for _, a := range s.adds {
		for _, ip := range a.Addrs {
			out[a.Set] = append(out[a.Set], ip.String())
		}
	}
	return out
}

var (
	up1 = netip.MustParseAddrPort("192.0.2.1:53")
	up2 = netip.MustParseAddrPort("192.0.2.2:53")
)

func newTestServer(u *upstreams, s *sets) *Server {
	return New(Options{
		Config: Config{
			Port:      5353,
			Upstreams: []netip.AddrPort{up1, up2},
			Uplinks:   []string{"ens3"},
			Sets: []DomainSet{
				{Set4: "l_ru_d4", Set6: "l_ru_d6", Domains: []string{"example.ru", "Other.RU."}},
				{Set4: "l_ext_d4", Set6: "l_ext_d6", Domains: []string{"cdn.test"}},
			},
		},
		Filler:     s,
		Exchanger:  u,
		Interfaces: func(string) (int, []netip.Addr, error) { return 0, nil, errors.New("absent") },
	})
}

func query(t *testing.T, name string, qtype uint16) []byte {
	t.Helper()
	q := new(dns.Msg)
	q.SetQuestion(name, qtype)
	b, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func unpack(t *testing.T, b []byte) *dns.Msg {
	t.Helper()
	if b == nil {
		t.Fatal("no reply")
	}
	m := new(dns.Msg)
	if err := m.Unpack(b); err != nil {
		t.Fatal(err)
	}
	return m
}

// A listed domain and its subdomains, in any case, fill the list's sets; a
// name that only ends like one does not.
func TestSuffixMatch(t *testing.T) {
	for _, tt := range []struct {
		name string
		want bool
	}{
		{"example.ru.", true},
		{"www.EXAMPLE.ru.", true},
		{"a.b.other.ru.", true},
		{"notexample.ru.", false},
		{"example.ru.evil.test.", false},
		{"ru.", false},
	} {
		s := &sets{}
		srv := newTestServer(&upstreams{answer: zone(tt.name + " 60 IN A 203.0.113.7")}, s)
		r := unpack(t, srv.answer(context.Background(), query(t, tt.name, dns.TypeA), false))
		if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1 {
			t.Errorf("%s: reply %v", tt.name, r)
		}
		got := slices.Equal(s.got()["l_ru_d4"], []string{"203.0.113.7"})
		if got != tt.want {
			t.Errorf("%s: in the set = %v, want %v (%v)", tt.name, got, tt.want, s.got())
		}
	}
}

// A CNAME chain counts every name on it: a foreign name pointing into a
// listed zone, or a listed name pointing out of it. HTTPS hints count as
// addresses, IPv6 goes to the IPv6 set.
func TestChainsAndHints(t *testing.T) {
	s := &sets{}
	srv := newTestServer(&upstreams{answer: zone(
		"www.site.test. 60 IN CNAME edge.cdn.test.",
		"edge.cdn.test. 60 IN A 198.51.100.1",
		"edge.cdn.test. 60 IN AAAA 2001:db8::1",
	)}, s)
	unpack(t, srv.answer(context.Background(), query(t, "www.site.test.", dns.TypeA), false))
	want := map[string][]string{"l_ext_d4": {"198.51.100.1"}, "l_ext_d6": {"2001:db8::1"}}
	if got := s.got(); !equalSets(got, want) {
		t.Fatalf("sets %v, want %v", got, want)
	}

	s = &sets{}
	srv = newTestServer(&upstreams{answer: zone(
		`example.ru. 60 IN HTTPS 1 . alpn="h2" ipv4hint="198.51.100.9" ipv6hint="2001:db8::9"`,
	)}, s)
	unpack(t, srv.answer(context.Background(), query(t, "example.ru.", dns.TypeHTTPS), false))
	want = map[string][]string{"l_ru_d4": {"198.51.100.9"}, "l_ru_d6": {"2001:db8::9"}}
	if got := s.got(); !equalSets(got, want) {
		t.Fatalf("sets %v, want %v", got, want)
	}
}

func equalSets(a, b map[string][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if !slices.Equal(v, b[k]) {
			return false
		}
	}
	return true
}

// A list whose IPv6 is blocked while its IPv4 goes through the exit is
// answered without IPv6 — AAAA records and IPv6 hints — so clients connect over
// IPv4; an AAAA question gets an empty answer. Other lists keep theirs.
func TestNoAAAA(t *testing.T) {
	newServer := func(u *upstreams, s *sets) *Server {
		return New(Options{
			Config: Config{Port: 5353, Upstreams: []netip.AddrPort{up1}, Sets: []DomainSet{
				{Set4: "l_ru_d4", Set6: "l_ru_d6", Domains: []string{"ru"}, NoAAAA: true},
			}},
			Filler: s, Exchanger: u,
			Interfaces: func(string) (int, []netip.Addr, error) { return 0, nil, errors.New("absent") },
		})
	}
	s := &sets{}
	srv := newServer(&upstreams{answer: zone(
		"www.ya.ru. 60 IN CNAME ya.ru.",
		"ya.ru. 60 IN AAAA 2a02:6b8::2:242",
	)}, s)
	r := unpack(t, srv.answer(context.Background(), query(t, "www.ya.ru.", dns.TypeAAAA), false))
	if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1 || r.Answer[0].Header().Rrtype != dns.TypeCNAME {
		t.Fatalf("AAAA reply %v", r)
	}
	if len(s.got()) != 0 {
		t.Fatalf("stripped addresses reached the sets: %v", s.got())
	}

	srv = newServer(&upstreams{answer: zone(
		`ya.ru. 60 IN HTTPS 1 . alpn="h2" ipv4hint="77.88.55.242" ipv6hint="2a02:6b8::2:242"`,
	)}, s)
	r = unpack(t, srv.answer(context.Background(), query(t, "ya.ru.", dns.TypeHTTPS), false))
	if strings.Contains(r.Answer[0].String(), "ipv6hint") || !strings.Contains(r.Answer[0].String(), "ipv4hint") {
		t.Fatalf("HTTPS reply %v", r.Answer[0])
	}

	srv = newServer(&upstreams{answer: zone("example.com. 60 IN AAAA 2001:db8::1")}, s)
	r = unpack(t, srv.answer(context.Background(), query(t, "example.com.", dns.TypeAAAA), false))
	if len(r.Answer) != 1 {
		t.Fatalf("an unlisted AAAA was stripped: %v", r)
	}
}

// An address that did not reach its set is never handed out: the client gets
// SERVFAIL. An unlisted answer does not touch the sets at all.
func TestFailedAddIsServfail(t *testing.T) {
	s := &sets{err: errors.New("no such set")}
	srv := newTestServer(&upstreams{answer: zone("example.ru. 60 IN A 203.0.113.7")}, s)
	r := unpack(t, srv.answer(context.Background(), query(t, "example.ru.", dns.TypeA), false))
	if r.Rcode != dns.RcodeServerFailure || len(r.Answer) != 0 {
		t.Fatalf("reply %v", r)
	}

	srv = newTestServer(&upstreams{answer: zone("foreign.test. 60 IN A 203.0.113.8")}, s)
	r = unpack(t, srv.answer(context.Background(), query(t, "foreign.test.", dns.TypeA), false))
	if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1 {
		t.Fatalf("unlisted reply %v", r)
	}
}

// NXDOMAIN and friends add nothing, even with records in them.
func TestOnlySuccessAdds(t *testing.T) {
	s := &sets{}
	srv := newTestServer(&upstreams{answer: func(up netip.AddrPort, n string, q *dns.Msg) *dns.Msg {
		r := zone("example.ru. 60 IN A 203.0.113.7")(up, n, q)
		r.Rcode = dns.RcodeNameError
		return r
	}}, s)
	unpack(t, srv.answer(context.Background(), query(t, "example.ru.", dns.TypeA), false))
	if len(s.got()) != 0 {
		t.Fatalf("sets %v", s.got())
	}
}

// The reply carries the client's ID, not the one sent upstream.
func TestReplyID(t *testing.T) {
	var sent uint16
	srv := newTestServer(&upstreams{answer: func(up netip.AddrPort, n string, q *dns.Msg) *dns.Msg {
		sent = q.Id
		return zone("foreign.test. 60 IN A 203.0.113.8")(up, n, q)
	}}, &sets{})
	q := new(dns.Msg)
	q.SetQuestion("foreign.test.", dns.TypeA)
	q.Id = 4242
	b, _ := q.Pack()
	r := unpack(t, srv.answer(context.Background(), b, false))
	if r.Id != 4242 {
		t.Fatalf("reply id %d", r.Id)
	}
	if sent == 4242 {
		t.Log("upstream id equals the client's (possible, 1 in 65536)")
	}
}

// A dead upstream is skipped and the one that answered is asked first next
// time; SERVFAIL moves on too; nobody answering is SERVFAIL.
func TestUpstreamFailover(t *testing.T) {
	u := &upstreams{answer: func(up netip.AddrPort, n string, q *dns.Msg) *dns.Msg {
		if up == up1 {
			return nil
		}
		return zone("foreign.test. 60 IN A 203.0.113.8")(up, n, q)
	}}
	srv := newTestServer(u, &sets{})
	for range 2 {
		r := unpack(t, srv.answer(context.Background(), query(t, "foreign.test.", dns.TypeA), false))
		if r.Rcode != dns.RcodeSuccess {
			t.Fatalf("reply %v", r)
		}
	}
	want := []string{"udp " + up1.String(), "udp " + up2.String(), "udp " + up2.String()}
	if !slices.Equal(u.asked, want) {
		t.Fatalf("asked %v, want %v", u.asked, want)
	}

	u = &upstreams{answer: func(up netip.AddrPort, n string, q *dns.Msg) *dns.Msg {
		r := new(dns.Msg)
		r.SetRcode(q, dns.RcodeServerFailure)
		if up == up2 {
			return zone("foreign.test. 60 IN A 203.0.113.8")(up, n, q)
		}
		return r
	}}
	r := unpack(t, newTestServer(u, &sets{}).answer(context.Background(), query(t, "foreign.test.", dns.TypeA), false))
	if r.Rcode != dns.RcodeSuccess {
		t.Fatalf("SERVFAIL was not passed over: %v", r)
	}

	u = &upstreams{answer: func(netip.AddrPort, string, *dns.Msg) *dns.Msg { return nil }}
	r = unpack(t, newTestServer(u, &sets{}).answer(context.Background(), query(t, "foreign.test.", dns.TypeA), false))
	if r.Rcode != dns.RcodeServerFailure {
		t.Fatalf("reply %v", r)
	}
}

// A truncated UDP answer is fetched again over TCP, and what the client
// cannot take over UDP is cut with TC set.
func TestTruncation(t *testing.T) {
	var records []string
	for i := range 60 {
		records = append(records, "big.test. 60 IN TXT \""+strings.Repeat("x", 50)+string(rune('a'+i%26))+"\"")
	}
	u := &upstreams{answer: func(up netip.AddrPort, network string, q *dns.Msg) *dns.Msg {
		r := zone(records...)(up, network, q)
		if network == "udp" {
			r.Answer, r.Truncated = nil, true
		}
		return r
	}}
	srv := newTestServer(u, &sets{})
	r := unpack(t, srv.answer(context.Background(), query(t, "big.test.", dns.TypeTXT), false))
	if !r.Truncated {
		t.Fatalf("a reply too long for UDP is not marked truncated: %d answers", len(r.Answer))
	}
	if !slices.Equal(u.asked, []string{"udp " + up1.String(), "tcp " + up1.String()}) {
		t.Fatalf("asked %v", u.asked)
	}
	r = unpack(t, srv.answer(context.Background(), query(t, "big.test.", dns.TypeTXT), true))
	if r.Truncated || len(r.Answer) != len(records) {
		t.Fatalf("TCP reply truncated=%v answers=%d", r.Truncated, len(r.Answer))
	}
}

// The liveness probe is answered without the upstreams; other CHAOS
// questions, other opcodes and garbage are not forwarded.
func TestLocalAnswers(t *testing.T) {
	u := &upstreams{answer: func(netip.AddrPort, string, *dns.Msg) *dns.Msg { t.Error("forwarded"); return nil }}
	srv := newTestServer(u, &sets{})

	q := new(dns.Msg)
	q.SetQuestion("version.bind.", dns.TypeTXT)
	q.Question[0].Qclass = dns.ClassCHAOS
	b, _ := q.Pack()
	r := unpack(t, srv.answer(context.Background(), b, false))
	if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1 {
		t.Fatalf("version.bind: %v", r)
	}

	q.SetQuestion("hostname.bind.", dns.TypeTXT)
	q.Question[0].Qclass = dns.ClassCHAOS
	b, _ = q.Pack()
	if r := unpack(t, srv.answer(context.Background(), b, false)); r.Rcode != dns.RcodeRefused {
		t.Fatalf("hostname.bind: %v", r)
	}

	q = new(dns.Msg)
	q.SetUpdate("example.ru.")
	b, _ = q.Pack()
	if r := unpack(t, srv.answer(context.Background(), b, false)); r.Rcode != dns.RcodeNotImplemented {
		t.Fatalf("update: %v", r)
	}

	if srv.answer(context.Background(), []byte{1, 2, 3}, false) != nil {
		t.Fatal("garbage answered")
	}
}

// Over the network: an answer comes back from the address asked, over UDP and
// TCP; a query arriving on an uplink gets nothing.
func TestServe(t *testing.T) {
	port := freePort(t)
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skip("no loopback interface")
	}
	for _, uplink := range []bool{false, true} {
		ifs := func(string) (int, []netip.Addr, error) {
			if !uplink {
				return 0, nil, errors.New("absent")
			}
			return lo.Index, []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}
		s := &sets{}
		srv := New(Options{
			Config: Config{Port: port, Upstreams: []netip.AddrPort{up1}, Uplinks: []string{"lo"},
				Sets: []DomainSet{{Set4: "l_ru_d4", Set6: "l_ru_d6", Domains: []string{"ru"}}}},
			Filler: s, Exchanger: &upstreams{answer: zone("ya.ru. 60 IN A 203.0.113.7")}, Interfaces: ifs,
		})
		ctx, cancel := context.WithCancel(context.Background())
		ready := make(chan struct{})
		done := make(chan error, 1)
		go func() { done <- srv.Serve(ctx, func() { close(ready) }) }()
		select {
		case <-ready:
		case err := <-done:
			t.Fatalf("serve: %v", err)
		}

		for _, network := range []string{"udp", "tcp"} {
			c := dns.Client{Net: network, Timeout: 300 * time.Millisecond}
			q := new(dns.Msg)
			q.SetQuestion("ya.ru.", dns.TypeA)
			r, _, err := c.Exchange(q, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port).String())
			switch {
			case uplink && err == nil:
				t.Errorf("%s: answered on an uplink: %v", network, r)
			case !uplink && (err != nil || len(r.Answer) != 1):
				t.Errorf("%s: %v %v", network, r, err)
			}
		}
		cancel()
		if err := <-done; err != nil {
			t.Fatalf("serve: %v", err)
		}
	}
}

func freePort(t *testing.T) uint16 {
	t.Helper()
	for range 20 {
		pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := uint16(pc.LocalAddr().(*net.UDPAddr).Port)
		pc.Close()
		ln, err := net.Listen("tcp4", "0.0.0.0:"+strconv.Itoa(int(port)))
		if err == nil {
			ln.Close()
			return port
		}
	}
	t.Fatal("no free port")
	return 0
}
