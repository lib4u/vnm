package sockets_test

import (
	"net"
	"os"
	"slices"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/lib4u/vnm/internal/infrastructure/sockets"
	"github.com/lib4u/vnm/internal/testsupport"
)

func TestMain(m *testing.M) {
	os.Exit(testsupport.MainInNetns(m))
}

// The set must hold what serves clients and nothing that opens connections:
// a client socket in it would let that client's traffic bypass the policy.
func TestListeningKeepsServersOnly(t *testing.T) {
	testsupport.RequireInNetns(t)
	if out, err := testsupport.Shell("ip link set lo up && ip link add wgs type wireguard"); err != nil {
		t.Fatalf("%v %s", err, out)
	}

	// A kernel WireGuard socket, like an AmneziaWG node's: no process owns it.
	wg, err := wgctrl.New()
	if err != nil {
		t.Fatal(err)
	}
	defer wg.Close()
	key, _ := wgtypes.GeneratePrivateKey()
	port := 8851
	if err := wg.ConfigureDevice("wgs", wgtypes.Config{PrivateKey: &key, ListenPort: &port}); err != nil {
		t.Fatal(err)
	}
	if out, err := testsupport.Shell("ip link set wgs up"); err != nil {
		t.Fatalf("%v %s", err, out)
	}

	tcpServer, err := net.Listen("tcp", "127.0.0.1:2222")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpServer.Close()
	udpServer, err := net.ListenPacket("udp", "0.0.0.0:443")
	if err != nil {
		t.Fatal(err)
	}
	defer udpServer.Close()
	// An outbound UDP socket that sends with sendto: never connected, port
	// from the ephemeral range.
	unconnected, err := net.ListenPacket("udp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer unconnected.Close()
	// A connected UDP client and a TCP client.
	connected, err := net.Dial("udp", "127.0.0.1:443")
	if err != nil {
		t.Fatal(err)
	}
	defer connected.Close()
	tcpClient, err := net.Dial("tcp", "127.0.0.1:2222")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpClient.Close()

	ports, err := sockets.NewReader("/proc").Listening()
	if err != nil {
		t.Fatalf("Listening: %v", err)
	}
	if !slices.Equal(ports.TCP, []uint16{2222}) {
		t.Errorf("tcp = %v, want [2222]", ports.TCP)
	}
	if !slices.Equal(ports.UDP, []uint16{443, 8851}) {
		t.Errorf("udp = %v, want [443 8851] — the kernel WireGuard port and the server, no client sockets", ports.UDP)
	}
}
