// Package ndpid reads the flow events of nDPId (p2p ТЗ §3.3).
//
// nDPId classifies flows with libnDPI and writes one JSON event per message
// to a collector socket: five ASCII digits of length, then the JSON. Every
// reader thread of nDPId opens a connection of its own, so the listener
// accepts any number of them. nDPId connects; the agent listens.
//
// Only what the p2p part needs is read: the flow's addresses and ports, the
// protocol nDPI found and whether packet inspection found it, as opposed to a
// guess from a port or an address.
package ndpid

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// Event is one flow event of nDPId.
type Event struct {
	// Name is the flow event: "new", "detected", "detection-update",
	// "guessed", "idle", "end", …
	Name     string
	L4       string
	Src, Dst netip.Addr
	SrcPort  uint16
	DstPort  uint16
	// Proto is nDPI's protocol, a master and an application joined by a dot
	// ("TLS.BitTorrent") or one name ("BitTorrent").
	Proto string
	// DPI means packet inspection found the protocol, not a port or an
	// address match.
	DPI bool
	// Source is the interface or file nDPId read the flow from.
	Source string
	// InfoHash is the torrent's info hash, when nDPI saw one.
	InfoHash string
}

// BitTorrent reports whether nDPI found BitTorrent in the flow, alone or as
// the application over another protocol.
func (e Event) BitTorrent() bool {
	for part := range strings.SplitSeq(e.Proto, ".") {
		if part == "BitTorrent" {
			return true
		}
	}
	return false
}

// Verdict reports whether the event carries a classification to act on: the
// flow was detected, or its detection changed.
func (e Event) Verdict() bool {
	return e.Name == "detected" || e.Name == "detection-update"
}

// message is the part of an nDPId event this package reads.
type message struct {
	FlowEventName string `json:"flow_event_name"`
	L4Proto       string `json:"l4_proto"`
	SrcIP         string `json:"src_ip"`
	DstIP         string `json:"dst_ip"`
	SrcPort       uint16 `json:"src_port"`
	DstPort       uint16 `json:"dst_port"`
	Source        string `json:"source"`
	NDPI          *struct {
		Proto      string            `json:"proto"`
		Confidence map[string]string `json:"confidence"`
		BitTorrent *struct {
			Hash string `json:"hash"`
		} `json:"bittorrent"`
	} `json:"ndpi"`
}

// maxMessage is the largest message five digits of length can announce.
const maxMessage = 99999

// ErrFraming means the stream is not nDPId's: a length that is not five
// digits. The connection cannot be resynchronised and is closed.
var ErrFraming = errors.New("ndpid: bad message framing")

// Decode reads messages until the stream ends and calls fn with every flow
// event that carries a protocol. Daemon, error and packet events are skipped,
// as is a flow event whose JSON does not parse: one bad message must not cost
// the rest of the stream.
func Decode(r io.Reader, fn func(Event)) error {
	br := bufio.NewReaderSize(r, 64*1024)
	head := make([]byte, 5)
	buf := make([]byte, 0, 4096)
	for {
		if _, err := io.ReadFull(br, head); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		n, err := strconv.Atoi(string(head))
		if err != nil || n <= 0 || n > maxMessage {
			return fmt.Errorf("%w: length %q", ErrFraming, head)
		}
		if cap(buf) < n {
			buf = make([]byte, n)
		}
		buf = buf[:n]
		if _, err := io.ReadFull(br, buf); err != nil {
			return err
		}
		if ev, ok := parse(buf); ok {
			fn(ev)
		}
	}
}

func parse(data []byte) (Event, bool) {
	var m message
	if err := json.Unmarshal(data, &m); err != nil || m.FlowEventName == "" || m.NDPI == nil || m.NDPI.Proto == "" {
		return Event{}, false
	}
	src, err1 := netip.ParseAddr(m.SrcIP)
	dst, err2 := netip.ParseAddr(m.DstIP)
	if err1 != nil || err2 != nil {
		return Event{}, false
	}
	ev := Event{
		Name: m.FlowEventName, L4: m.L4Proto,
		Src: src.Unmap(), Dst: dst.Unmap(), SrcPort: m.SrcPort, DstPort: m.DstPort,
		Proto: m.NDPI.Proto, Source: m.Source,
	}
	for _, how := range m.NDPI.Confidence {
		// "DPI", "DPI (partial)", "DPI (cache)", "DPI (aggressive)" …; not
		// "Match by port" or "Match by IP".
		if strings.HasPrefix(how, "DPI") {
			ev.DPI = true
		}
	}
	if m.NDPI.BitTorrent != nil {
		ev.InfoHash = m.NDPI.BitTorrent.Hash
	}
	return ev, true
}

// Listener accepts nDPId's connections on a UNIX socket and hands their
// events to a handler.
type Listener struct {
	conns atomic.Int64
	// Faults counts connections ended by a fault while reading them.
	Faults atomic.Int64
}

// Connections returns how many nDPId connections are open: zero means nDPId
// is not writing.
func (l *Listener) Connections() int64 { return l.conns.Load() }

// Serve listens on path until ctx ends. A connection that fails — a broken
// stream, or a fault reading it — ends alone: what nDPId writes is input from
// another process, and must never take the agent down with it. The socket is created anew — a stale
// one from a crashed agent is removed — and, with its directory, made
// reachable and writable by gid, the group nDPId runs as: connecting to a
// socket takes search permission on its directory. handle is called from one
// goroutine per connection.
func (l *Listener) Serve(ctx context.Context, path string, gid int, handle func(Event)) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("socket directory: %w", err)
	}
	if err := os.Chown(dir, -1, gid); err != nil {
		return fmt.Errorf("chown %s: %w", dir, err)
	}
	if err := os.Chmod(dir, 0o750); err != nil {
		return fmt.Errorf("chmod %s: %w", dir, err)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove stale socket: %w", err)
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return fmt.Errorf("listen %s: %w", path, err)
	}
	ln.SetUnlinkOnClose(true)
	if err := os.Chown(path, -1, gid); err != nil {
		ln.Close()
		return fmt.Errorf("chown %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o660); err != nil {
		ln.Close()
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	var wg sync.WaitGroup
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	defer wg.Wait()
	for {
		conn, err := ln.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept: %w", err)
		}
		wg.Add(1)
		l.conns.Add(1)
		go func() {
			defer wg.Done()
			defer l.conns.Add(-1)
			defer conn.Close()
			stop := context.AfterFunc(ctx, func() { conn.Close() })
			defer stop()
			defer func() {
				if r := recover(); r != nil {
					l.Faults.Add(1)
				}
			}()
			_ = Decode(conn, handle) // a broken stream ends its connection only
		}()
	}
}
