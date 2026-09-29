package wgexit_test

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"

	"github.com/lib4u/vnm/internal/domain/policy"
	"github.com/lib4u/vnm/internal/infrastructure/runner"
	"github.com/lib4u/vnm/internal/infrastructure/wgexit"
	"github.com/lib4u/vnm/internal/testsupport"
)

func TestMain(m *testing.M) {
	os.Exit(testsupport.MainInNetns(m))
}

var (
	firstEndpoint  = netip.MustParseAddrPort("192.0.2.1:2408")
	secondEndpoint = netip.MustParseAddrPort("192.0.2.1:500")
)

func setupDevice(t *testing.T) (*wgexit.Device, policy.Exit) {
	t.Helper()
	testsupport.RequireInNetns(t)
	conf := filepath.Join(t.TempDir(), "warp.conf")
	if err := os.WriteFile(conf, []byte(confText(t)), 0o600); err != nil {
		t.Fatal(err)
	}
	dev, err := wgexit.NewDevice(runner.System{Timeout: 10 * time.Second}, "/proc/sys")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dev.Close() })
	exit := policy.Exit{Name: "warp", Iface: "warp", Conf: conf, Endpoints: []netip.AddrPort{firstEndpoint, secondEndpoint}}
	t.Cleanup(func() { dev.Remove(context.Background(), exit.Iface) })
	return dev, exit
}

func peerEndpoint(t *testing.T, iface string) netip.AddrPort {
	t.Helper()
	c, err := wgctrl.New()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	d, err := c.Device(iface)
	if err != nil || len(d.Peers) != 1 {
		t.Fatalf("device %s: %+v %v", iface, d, err)
	}
	return d.Peers[0].Endpoint.AddrPort()
}

func TestRecreateStateEnsureRemove(t *testing.T) {
	dev, exit := setupDevice(t)
	ctx := context.Background()

	state, err := dev.State(ctx, exit)
	if err != nil || state.Up {
		t.Fatalf("before create: %+v %v", state, err)
	}

	if err := dev.Recreate(ctx, exit, firstEndpoint); err != nil {
		t.Fatalf("Recreate: %v", err)
	}
	state, err = dev.State(ctx, exit)
	if err != nil || !state.Up || state.HandshakeAge != 0 {
		t.Fatalf("after create: %+v %v (no peer answers, so no handshake)", state, err)
	}
	rp, err := os.ReadFile("/proc/sys/net/ipv4/conf/warp/rp_filter")
	if err != nil || strings.TrimSpace(string(rp)) != "2" {
		t.Fatalf("rp_filter = %q %v, want loose (2)", rp, err)
	}

	// Ensure with the same endpoint changes nothing; with another it moves the
	// peer there.
	if err := dev.Ensure(ctx, exit, firstEndpoint); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if got := peerEndpoint(t, "warp"); got != firstEndpoint {
		t.Fatalf("endpoint = %v", got)
	}
	if err := dev.Ensure(ctx, exit, secondEndpoint); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if got := peerEndpoint(t, "warp"); got != secondEndpoint {
		t.Fatalf("endpoint after switch = %v, want %v", got, secondEndpoint)
	}

	if err := dev.Remove(ctx, exit.Iface); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if state, _ := dev.State(ctx, exit); state.Up {
		t.Fatal("interface still up after Remove")
	}
	if err := dev.Remove(ctx, exit.Iface); err != nil {
		t.Fatalf("second Remove must be a no-op: %v", err)
	}
}

// Recreating over an existing interface replaces it instead of failing.
func TestRecreateOverExisting(t *testing.T) {
	dev, exit := setupDevice(t)
	ctx := context.Background()
	for range 2 {
		if err := dev.Recreate(ctx, exit, firstEndpoint); err != nil {
			t.Fatalf("Recreate: %v", err)
		}
	}
}
