package resolver_test

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/lib4u/vnm/internal/infrastructure/resolver"
)

func TestAnswers(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			buf[2] |= 0x80 // a response to the same ID
			_, _ = conn.WriteTo(buf[:n], from)
		}
	}()
	addr := conn.LocalAddr().(*net.UDPAddr).AddrPort()
	if !resolver.Answers(context.Background(), addr) {
		t.Fatal("a server that answers is reported down")
	}
}

func TestAnswersNobodyListening(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := conn.LocalAddr().(*net.UDPAddr).AddrPort()
	conn.Close()
	if resolver.Answers(context.Background(), netip.AddrPortFrom(addr.Addr(), addr.Port())) {
		t.Fatal("a closed port is reported up")
	}
}
