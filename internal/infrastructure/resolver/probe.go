package resolver

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"net/netip"
	"time"
)

// probeTimeout bounds a liveness query; a resolver on loopback answers in
// microseconds.
const probeTimeout = 2 * time.Second

// versionQuery is a DNS query for "version.bind" TXT in the CHAOS class, less
// its ID. dnsmasq answers it itself, without its upstreams, so an answer
// proves the resolver serves on the port and nothing more.
var versionQuery = []byte{
	0x01, 0x00, // flags: recursion desired
	0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // one question
	7, 'v', 'e', 'r', 's', 'i', 'o', 'n', 4, 'b', 'i', 'n', 'd', 0,
	0x00, 0x10, // TXT
	0x00, 0x03, // CHAOS
}

// Answers reports whether a DNS server answers at addr over UDP.
func Answers(ctx context.Context, addr netip.AddrPort) bool {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", addr.String())
	if err != nil {
		return false
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return false
		}
	}

	var id [2]byte
	if _, err := rand.Read(id[:]); err != nil {
		return false
	}
	if _, err := conn.Write(append(id[:], versionQuery...)); err != nil {
		return false
	}
	reply := make([]byte, 512)
	n, err := conn.Read(reply)
	const isResponse = 0x80
	return err == nil && n >= 12 &&
		binary.BigEndian.Uint16(reply) == binary.BigEndian.Uint16(id[:]) &&
		reply[2]&isResponse != 0
}
