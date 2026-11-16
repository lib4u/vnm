package resolver_test

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/lib4u/vnm/internal/infrastructure/dnsd"
	"github.com/lib4u/vnm/internal/infrastructure/resolver"
)

// server answers CHAOS TXT queries with txt after ignoring the first `lose`
// queries, and counts what it was asked.
type server struct {
	lose  int64
	txt   string
	asked atomic.Int64
}

func (s *server) start(t *testing.T) netip.AddrPort {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			if s.asked.Add(1) <= s.lose {
				continue
			}
			q := new(dns.Msg)
			if q.Unpack(buf[:n]) != nil {
				continue
			}
			r := new(dns.Msg)
			r.SetReply(q)
			r.Answer = []dns.RR{&dns.TXT{
				Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassCHAOS},
				Txt: []string{s.txt},
			}}
			out, _ := r.Pack()
			_, _ = conn.WriteTo(out, from)
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr).AddrPort()
}

func shortAttempts(t *testing.T) {
	t.Helper()
	old := *resolver.AttemptTimeout
	*resolver.AttemptTimeout = 50 * time.Millisecond
	t.Cleanup(func() { *resolver.AttemptTimeout = old })
}

func TestAnswers(t *testing.T) {
	s := &server{txt: "vnm"}
	if !resolver.Answers(context.Background(), s.start(t)) {
		t.Fatal("a server that answers is reported down")
	}
	if s.asked.Load() != 1 {
		t.Fatalf("asked %d times, want once", s.asked.Load())
	}
}

// A lost datagram is not a dead resolver: the probe asks again, and gives up
// only when every attempt went unanswered.
func TestAnswersRetriesLostQueries(t *testing.T) {
	shortAttempts(t)
	s := &server{lose: resolver.ProbeAttempts - 1, txt: "vnm"}
	if !resolver.Answers(context.Background(), s.start(t)) {
		t.Fatal("a resolver that answered the last attempt is reported down")
	}
	s = &server{lose: resolver.ProbeAttempts, txt: "vnm"}
	if resolver.Answers(context.Background(), s.start(t)) {
		t.Fatal("a resolver that answered nothing is reported up")
	}
	if s.asked.Load() != resolver.ProbeAttempts {
		t.Fatalf("asked %d times, want %d", s.asked.Load(), resolver.ProbeAttempts)
	}
}

func TestAnswersNobodyListening(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := conn.LocalAddr().(*net.UDPAddr).AddrPort()
	conn.Close()
	start := time.Now()
	if resolver.Answers(context.Background(), addr) {
		t.Fatal("a closed port is reported up")
	}
	// A closed port refuses each attempt at once: no timeouts to wait out.
	if took := time.Since(start); took > time.Second {
		t.Fatalf("a closed port took %s to be reported down", took)
	}
}

func TestUDPDropped(t *testing.T) {
	s := &server{txt: "42"}
	n, err := resolver.UDPDropped(context.Background(), s.start(t))
	if err != nil || n != 42 {
		t.Fatalf("UDPDropped = %d, %v; want 42", n, err)
	}
	s = &server{txt: "many"}
	if _, err := resolver.UDPDropped(context.Background(), s.start(t)); err == nil {
		t.Fatal("a count that is not a number is read")
	}
}

// Against the resolver itself: the probe and the counter it reads are the
// ones it answers.
func TestProbesTheVnmResolver(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(pc.LocalAddr().(*net.UDPAddr).Port)
	pc.Close()
	srv := dnsd.New(dnsd.Options{
		Config:     dnsd.Config{Port: port, Upstreams: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:53")}},
		Interfaces: func(string) (int, []netip.Addr, error) { return 0, nil, net.ErrClosed },
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, func() { close(ready) }) }()
	select {
	case <-ready:
	case err := <-done:
		t.Skipf("cannot serve on port %d: %v", port, err)
	}
	addr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)
	if !resolver.Answers(ctx, addr) {
		t.Fatal("the vnm resolver is reported down")
	}
	if n, err := resolver.UDPDropped(ctx, addr); err != nil || n != 0 {
		t.Fatalf("UDPDropped = %d, %v", n, err)
	}
	cancel()
	<-done
}
