package dnsd

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"
)

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

// Every in-flight slot taken: a client's query is dropped and counted, while
// the agent's probe and its read of that count are still answered — a busy
// resolver is not a dead one.
func TestHostProbeBypassesInFlightLimit(t *testing.T) {
	port := freePort(t)
	srv := New(Options{
		Config: Config{Port: port, Upstreams: []netip.AddrPort{up1},
			Sets: []DomainSet{{Set4: "l_ru_d4", Set6: "l_ru_d6", Domains: []string{"ru"}}}},
		Filler: &sets{}, Exchanger: &upstreams{answer: zone("ya.ru. 60 IN A 203.0.113.7")},
		Interfaces: func(string) (int, []netip.Addr, error) { return 0, nil, errors.New("absent") },
	})
	for range cap(srv.udp) {
		srv.udp <- struct{}{}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, func() { close(ready) }) }()
	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("serve: %v", err)
	}
	addr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port).String()
	c := dns.Client{Net: "udp", Timeout: 300 * time.Millisecond}

	q := new(dns.Msg)
	q.SetQuestion("ya.ru.", dns.TypeA)
	if r, _, err := c.Exchange(q, addr); err == nil {
		t.Fatalf("answered over the in-flight limit: %v", r)
	}
	chaos := func(name string) *dns.Msg {
		t.Helper()
		q := new(dns.Msg)
		q.SetQuestion(name, dns.TypeTXT)
		q.Question[0].Qclass = dns.ClassCHAOS
		r, _, err := c.Exchange(q, addr)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return r
	}
	if r := chaos(VersionName); r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1 {
		t.Fatalf("probe while busy: %v", r)
	}
	r := chaos(UDPDroppedName)
	if txt, ok := r.Answer[0].(*dns.TXT); !ok || txt.Txt[0] != "1" {
		t.Fatalf("drop count: %v", r)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("serve: %v", err)
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
