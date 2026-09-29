package dnsd

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// Serve listens on the port over UDP and TCP, IPv4 and IPv6, until ctx ends;
// ready is called once every listener is bound. A host without IPv6 is served
// over IPv4 alone.
func (s *Server) Serve(ctx context.Context, ready func()) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var lc net.ListenConfig
	addr4 := fmt.Sprintf("0.0.0.0:%d", s.port)
	addr6 := fmt.Sprintf("[::]:%d", s.port)
	var closers []io.Closer
	defer func() {
		for _, c := range closers {
			_ = c.Close()
		}
	}()

	var udps []udpConn
	var tcps []net.Listener
	pc4, err := lc.ListenPacket(ctx, "udp4", addr4)
	if err != nil {
		return err
	}
	closers = append(closers, pc4)
	u4, err := newUDP4(pc4)
	if err != nil {
		return err
	}
	udps = append(udps, u4)
	ln4, err := lc.Listen(ctx, "tcp4", addr4)
	if err != nil {
		return err
	}
	closers = append(closers, ln4)
	tcps = append(tcps, ln4)

	if pc6, err := lc.ListenPacket(ctx, "udp6", addr6); err != nil {
		s.log.warn("ipv6", "no IPv6: served over IPv4 alone", "err", err)
	} else {
		closers = append(closers, pc6)
		u6, err := newUDP6(pc6)
		if err != nil {
			return err
		}
		udps = append(udps, u6)
		if ln6, err := lc.Listen(ctx, "tcp6", addr6); err != nil {
			s.log.warn("ipv6", "no IPv6 over TCP", "err", err)
		} else {
			closers = append(closers, ln6)
			tcps = append(tcps, ln6)
		}
	}
	if ready != nil {
		ready()
	}

	var wg sync.WaitGroup
	errs := make(chan error, len(udps)+len(tcps))
	for _, u := range udps {
		wg.Go(func() { errs <- s.serveUDP(ctx, u) })
	}
	for _, ln := range tcps {
		wg.Go(func() { errs <- s.serveTCP(ctx, ln) })
	}
	wg.Go(func() {
		t := time.NewTicker(refreshEvery)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.uplinks.refresh()
			}
		}
	})

	var first error
	select {
	case <-ctx.Done():
	case first = <-errs:
	}
	cancel()
	for _, c := range closers {
		_ = c.Close()
	}
	closers = nil
	wg.Wait()
	return first
}

// udpConn reads a datagram with the interface it arrived on and the address it
// was sent to, and answers from that address.
type udpConn interface {
	read(buf []byte) (n int, dst net.IP, ifIndex int, src net.Addr, err error)
	write(b []byte, from net.IP, to net.Addr) error
}

type udp4 struct{ pc *ipv4.PacketConn }

func newUDP4(c net.PacketConn) (udp4, error) {
	pc := ipv4.NewPacketConn(c)
	if err := pc.SetControlMessage(ipv4.FlagDst|ipv4.FlagInterface, true); err != nil {
		return udp4{}, fmt.Errorf("udp4 packet info: %w", err)
	}
	return udp4{pc}, nil
}

func (u udp4) read(buf []byte) (int, net.IP, int, net.Addr, error) {
	n, cm, src, err := u.pc.ReadFrom(buf)
	if err != nil || cm == nil {
		return n, nil, 0, src, err
	}
	return n, cm.Dst, cm.IfIndex, src, nil
}

func (u udp4) write(b []byte, from net.IP, to net.Addr) error {
	_, err := u.pc.WriteTo(b, &ipv4.ControlMessage{Src: from}, to)
	return err
}

type udp6 struct{ pc *ipv6.PacketConn }

func newUDP6(c net.PacketConn) (udp6, error) {
	pc := ipv6.NewPacketConn(c)
	if err := pc.SetControlMessage(ipv6.FlagDst|ipv6.FlagInterface, true); err != nil {
		return udp6{}, fmt.Errorf("udp6 packet info: %w", err)
	}
	return udp6{pc}, nil
}

func (u udp6) read(buf []byte) (int, net.IP, int, net.Addr, error) {
	n, cm, src, err := u.pc.ReadFrom(buf)
	if err != nil || cm == nil {
		return n, nil, 0, src, err
	}
	return n, cm.Dst, cm.IfIndex, src, nil
}

func (u udp6) write(b []byte, from net.IP, to net.Addr) error {
	_, err := u.pc.WriteTo(b, &ipv6.ControlMessage{Src: from}, to)
	return err
}

// serveUDP answers datagrams. One that arrived on an uplink, or without the
// packet info that tells where it arrived, is dropped; so is one over the
// in-flight limit — the client asks again.
func (s *Server) serveUDP(ctx context.Context, u udpConn) error {
	buf := make([]byte, 65535)
	for {
		n, dst, ifIndex, src, err := u.read(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			s.log.warn("udp read", "udp read failed", "err", err)
			continue
		}
		if dst == nil || s.uplinks.hasIndex(ifIndex) {
			continue
		}
		select {
		case s.udp <- struct{}{}:
		default:
			s.log.warn("udp busy", "too many queries in flight; dropping")
			continue
		}
		req := bytes.Clone(buf[:n])
		go func() {
			defer func() { <-s.udp }()
			if reply := s.answer(ctx, req, false); reply != nil {
				if err := u.write(reply, dst, src); err != nil && ctx.Err() == nil {
					s.log.warn("udp write", "udp write failed", "err", err)
				}
			}
		}()
	}
}

// serveTCP accepts connections. One made to an address of an uplink is closed
// at once, as is one over the connection limit.
func (s *Server) serveTCP(ctx context.Context, ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			s.log.warn("tcp accept", "tcp accept failed", "err", err)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		local, ok := addrOf(c.LocalAddr())
		if !ok || s.uplinks.hasAddr(local) {
			_ = c.Close()
			continue
		}
		select {
		case s.tcp <- struct{}{}:
		default:
			s.log.warn("tcp busy", "too many TCP connections; closing")
			_ = c.Close()
			continue
		}
		go func() {
			defer func() { <-s.tcp }()
			defer c.Close()
			s.serveConn(ctx, c)
		}()
	}
}

// serveConn answers the queries of one connection until it goes idle.
func (s *Server) serveConn(ctx context.Context, c net.Conn) {
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	var size [2]byte
	for {
		if err := c.SetDeadline(time.Now().Add(tcpIdle)); err != nil {
			return
		}
		if _, err := io.ReadFull(c, size[:]); err != nil {
			return
		}
		req := make([]byte, binary.BigEndian.Uint16(size[:]))
		if _, err := io.ReadFull(c, req); err != nil {
			return
		}
		reply := s.answer(ctx, req, true)
		if reply == nil {
			return
		}
		out := binary.BigEndian.AppendUint16(make([]byte, 0, 2+len(reply)), uint16(len(reply)))
		if _, err := c.Write(append(out, reply...)); err != nil {
			return
		}
	}
}

func addrOf(a net.Addr) (netip.Addr, bool) {
	tcp, ok := a.(*net.TCPAddr)
	if !ok {
		return netip.Addr{}, false
	}
	addr, ok := netip.AddrFromSlice(tcp.IP)
	return addr.Unmap(), ok
}

// systemInterfaces looks an interface up in the host's network stack.
func systemInterfaces(name string) (int, []netip.Addr, error) {
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return 0, nil, err
	}
	raw, err := ifc.Addrs()
	if err != nil {
		return 0, nil, err
	}
	var addrs []netip.Addr
	for _, a := range raw {
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			addrs = append(addrs, p.Addr())
		}
	}
	return ifc.Index, addrs, nil
}
