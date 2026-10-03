package ndpid_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lib4u/vnm/internal/infrastructure/ndpid"
)

// The streams in testdata are what nDPId 1.7.0 (libnDPI 6.1) wrote for the
// pcaps of libnDPI's own tests, so the decoder is checked against the real
// format rather than a description of it.
func verdicts(t *testing.T, file string) []ndpid.Event {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", file))
	if err != nil {
		t.Fatal(err)
	}
	var out []ndpid.Event
	if err := ndpid.Decode(bytes.NewReader(data), func(e ndpid.Event) {
		if e.Verdict() {
			out = append(out, e)
		}
	}); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	return out
}

func TestDecodeBitTorrent(t *testing.T) {
	for file, want := range map[string]int{
		"bittorrent.stream":     24, // TCP peer connections
		"utp.stream":            4,  // uTP: detected, then detection-update
		"tls-bittorrent.stream": 3,  // BitTorrent over TLS
	} {
		t.Run(file, func(t *testing.T) {
			evs := verdicts(t, file)
			bt := 0
			for _, e := range evs {
				if e.BitTorrent() && e.DPI {
					bt++
				}
			}
			if bt != want {
				t.Fatalf("%d BitTorrent verdicts by DPI, want %d", bt, want)
			}
		})
	}
}

func TestDecodeFields(t *testing.T) {
	e := verdicts(t, "bittorrent.stream")[0]
	want := ndpid.Event{
		Name: "detected", L4: "tcp",
		Src: netip.MustParseAddr("192.168.1.3"), Dst: netip.MustParseAddr("82.58.216.115"),
		SrcPort: 52888, DstPort: 38305,
		Proto: "BitTorrent", DPI: true, Source: "pcap-all/bittorrent.pcap",
		InfoHash: "dcfcdccfb9e670ccc3dd40c78c161f2bea243126",
	}
	if e != want {
		t.Fatalf("event = %+v\nwant    %+v", e, want)
	}
}

// DNS over HTTPS is classified, and it is not BitTorrent.
func TestDecodeOtherProtocol(t *testing.T) {
	evs := verdicts(t, "doh.stream")
	if len(evs) == 0 {
		t.Fatal("no verdict")
	}
	for _, e := range evs {
		if e.BitTorrent() {
			t.Fatalf("%s read as BitTorrent", e.Proto)
		}
	}
}

func TestBitTorrentNames(t *testing.T) {
	for proto, want := range map[string]bool{
		"BitTorrent": true, "TLS.BitTorrent": true, "BitTorrent.Unknown": true,
		"TLS": false, "BitTorrentish": false, "": false, "QUIC.Google": false,
	} {
		if got := (ndpid.Event{Proto: proto}).BitTorrent(); got != want {
			t.Errorf("%q: BitTorrent() = %v", proto, got)
		}
	}
}

func TestDecodeRejectsBadFraming(t *testing.T) {
	err := ndpid.Decode(bytes.NewReader([]byte("12x45{}")), func(ndpid.Event) {})
	if !errors.Is(err, ndpid.ErrFraming) {
		t.Fatalf("error %v, want ErrFraming", err)
	}
}

// A message that does not parse is skipped; the rest of the stream is read.
func TestDecodeSkipsBadMessage(t *testing.T) {
	good := `{"flow_event_name":"detected","l4_proto":"udp","src_ip":"10.0.0.2","dst_ip":"198.51.100.7","src_port":1,"dst_port":2,"ndpi":{"proto":"BitTorrent","confidence":{"6":"DPI"}}}`
	var stream bytes.Buffer
	fmt.Fprintf(&stream, "%05d%s", len("{nope"), "{nope")
	fmt.Fprintf(&stream, "%05d%s", len(good), good)
	n := 0
	if err := ndpid.Decode(&stream, func(ndpid.Event) { n++ }); err != nil || n != 1 {
		t.Fatalf("n=%d err=%v, want the good message", n, err)
	}
}

// Messages larger than the decoder's first buffer — nDPId's detection events
// with flow risks and analysis run past 4 KiB — are read whole. This crashed
// the agent on a live node: the buffer was resliced before it was grown.
func TestDecodeLargeMessages(t *testing.T) {
	const head = `{"flow_event_name":"detected","l4_proto":"tcp","src_ip":"10.0.0.2","dst_ip":"198.51.100.7","src_port":1,"dst_port":2,"ndpi":{"proto":"BitTorrent","confidence":{"6":"DPI"}},"pad":"`
	var stream bytes.Buffer
	sizes := []int{300, 4096, 4435, 6049, 99999} // 99999: the most five digits announce
	for _, size := range sizes {
		msg := head + strings.Repeat("x", size-len(head)-2) + `"}`
		fmt.Fprintf(&stream, "%05d%s", len(msg), msg)
	}
	n := 0
	if err := ndpid.Decode(&stream, func(e ndpid.Event) {
		if e.BitTorrent() {
			n++
		}
	}); err != nil || n != len(sizes) {
		t.Fatalf("decoded %d of %d, err %v", n, len(sizes), err)
	}
}

// nDPId opens a connection per reader thread: every one is served.
func TestListenerServesManyConnections(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ndpid.sock")
	events := make(chan ndpid.Event, 8)
	var l ndpid.Listener
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- l.Serve(ctx, path, os.Getgid(), func(e ndpid.Event) { events <- e }) }()

	msg := `{"flow_event_name":"detected","l4_proto":"tcp","src_ip":"10.0.0.2","dst_ip":"198.51.100.7","src_port":40000,"dst_port":6881,"ndpi":{"proto":"BitTorrent","confidence":{"6":"DPI"}}}`
	var conns []net.Conn
	deadline := time.Now().Add(2 * time.Second)
	for len(conns) < 3 {
		c, err := net.Dial("unix", path)
		if err != nil {
			if time.Now().After(deadline) {
				t.Fatal(err)
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		conns = append(conns, c)
		fmt.Fprintf(c, "%05d%s", len(msg), msg)
	}
	for range conns {
		select {
		case e := <-events:
			if !e.BitTorrent() || e.DstPort != 6881 {
				t.Fatalf("event = %+v", e)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("an event did not arrive")
		}
	}
	if n := l.Connections(); n != 3 {
		t.Fatalf("connections = %d, want 3", n)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the socket outlived the listener")
	}
}
