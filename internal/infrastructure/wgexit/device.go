package wgexit

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/lib4u/vnm/internal/domain/policy"
	"github.com/lib4u/vnm/internal/infrastructure/runner"
	"github.com/lib4u/vnm/internal/usecase/exits"
)

// Device controls kernel WireGuard exit interfaces.
type Device struct {
	wg  *wgctrl.Client
	run runner.Runner
	// procSys is where sysctls are written, injectable for tests.
	procSys string
	now     func() time.Time
}

var _ exits.Device = (*Device)(nil)

// NewDevice opens the WireGuard control socket. Close releases it.
func NewDevice(run runner.Runner, procSys string) (*Device, error) {
	wg, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("open wireguard control: %w", err)
	}
	return &Device{wg: wg, run: run, procSys: procSys, now: time.Now}, nil
}

// Close releases the control socket.
func (d *Device) Close() error {
	return d.wg.Close()
}

// State reports whether the interface is up and how old its handshake is.
func (d *Device) State(_ context.Context, e policy.Exit) (exits.LinkState, error) {
	iface, found, err := findInterface(e.Iface)
	if err != nil || !found {
		// A missing interface is a state, not an error.
		return exits.LinkState{}, err
	}
	state := exits.LinkState{Up: iface.Flags&net.FlagUp != 0}
	dev, err := d.wg.Device(e.Iface)
	if err != nil {
		return exits.LinkState{}, fmt.Errorf("read %s: %w", e.Iface, err)
	}
	if len(dev.Peers) != 1 {
		return state, nil
	}
	peer := dev.Peers[0]
	if !peer.LastHandshakeTime.IsZero() {
		state.HandshakeAge = d.now().Sub(peer.LastHandshakeTime)
	}
	if peer.Endpoint != nil {
		state.Endpoint = peer.Endpoint.AddrPort()
	}
	return state, nil
}

// Ensure makes an existing interface match the config: the WireGuard side only
// when it differs (rewriting the peer would reset its handshake), the address,
// MTU and link state always — those writes are idempotent.
func (d *Device) Ensure(ctx context.Context, e policy.Exit, endpoint netip.AddrPort) error {
	conf, err := LoadConf(e.Conf)
	if err != nil {
		return err
	}
	dev, err := d.wg.Device(e.Iface)
	if err != nil {
		return fmt.Errorf("read %s: %w", e.Iface, err)
	}
	if !matches(dev, conf, endpoint) {
		if err := d.configure(e.Iface, conf, endpoint); err != nil {
			return err
		}
	}
	return d.setLink(ctx, e.Iface, conf)
}

// ResetPeer replaces the peer, which drops its session and forces a new
// handshake, at endpoint.
func (d *Device) ResetPeer(_ context.Context, e policy.Exit, endpoint netip.AddrPort) error {
	conf, err := LoadConf(e.Conf)
	if err != nil {
		return err
	}
	return d.configure(e.Iface, conf, endpoint)
}

// Recreate deletes the interface, if any, and builds it from the config.
func (d *Device) Recreate(ctx context.Context, e policy.Exit, endpoint netip.AddrPort) error {
	conf, err := LoadConf(e.Conf)
	if err != nil {
		return err
	}
	if err := d.Remove(ctx, e.Iface); err != nil {
		return err
	}
	if err := d.ip(ctx, "link", "add", "dev", e.Iface, "type", "wireguard"); err != nil {
		return err
	}
	if err := d.configure(e.Iface, conf, endpoint); err != nil {
		return err
	}
	return d.setLink(ctx, e.Iface, conf)
}

// Remove deletes an interface; a missing one is not an error.
func (d *Device) Remove(ctx context.Context, iface string) error {
	_, found, err := findInterface(iface)
	if err != nil || !found {
		return err
	}
	return d.ip(ctx, "link", "del", "dev", iface)
}

// findInterface looks an interface up by name. Listing and searching, rather
// than net.InterfaceByName, keeps "no such interface" apart from a real
// failure to read the interfaces.
func findInterface(name string) (net.Interface, bool, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return net.Interface{}, false, fmt.Errorf("list interfaces: %w", err)
	}
	for _, iface := range ifaces {
		if iface.Name == name {
			return iface, true, nil
		}
	}
	return net.Interface{}, false, nil
}

func (d *Device) configure(iface string, conf Conf, endpoint netip.AddrPort) error {
	allowed := make([]net.IPNet, 0, len(conf.Peer.AllowedIPs))
	for _, p := range conf.Peer.AllowedIPs {
		allowed = append(allowed, net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())})
	}
	keepalive := conf.Peer.Keepalive
	err := d.wg.ConfigureDevice(iface, wgtypes.Config{
		PrivateKey:   &conf.PrivateKey,
		ReplacePeers: true,
		Peers: []wgtypes.PeerConfig{{
			PublicKey:                   conf.Peer.PublicKey,
			Endpoint:                    net.UDPAddrFromAddrPort(endpoint),
			ReplaceAllowedIPs:           true,
			AllowedIPs:                  allowed,
			PersistentKeepaliveInterval: &keepalive,
		}},
	})
	if err != nil {
		return fmt.Errorf("configure %s: %w", iface, err)
	}
	return nil
}

// setLink sets the address, MTU, link state and loose reverse-path filtering:
// replies from the exit come back from addresses the main table routes
// elsewhere, and strict filtering would drop them.
func (d *Device) setLink(ctx context.Context, iface string, conf Conf) error {
	if err := d.ip(ctx, "address", "replace", conf.Address.String(), "dev", iface); err != nil {
		return err
	}
	if err := d.ip(ctx, "link", "set", "dev", iface, "mtu", strconv.Itoa(conf.MTU), "up"); err != nil {
		return err
	}
	path := filepath.Join(d.procSys, "net", "ipv4", "conf", iface, "rp_filter")
	if err := os.WriteFile(path, []byte("2"), 0o644); err != nil {
		return fmt.Errorf("set rp_filter on %s: %w", iface, err)
	}
	return nil
}

func (d *Device) ip(ctx context.Context, args ...string) error {
	_, err := d.run.Run(ctx, runner.Command{Name: "ip", Args: args})
	return err
}

// matches reports whether the device already holds the config at endpoint.
func matches(dev *wgtypes.Device, conf Conf, endpoint netip.AddrPort) bool {
	if dev.PrivateKey != conf.PrivateKey || len(dev.Peers) != 1 {
		return false
	}
	peer := dev.Peers[0]
	if peer.PublicKey != conf.Peer.PublicKey || peer.PersistentKeepaliveInterval != conf.Peer.Keepalive {
		return false
	}
	if peer.Endpoint == nil || peer.Endpoint.AddrPort() != endpoint {
		return false
	}
	have := make([]netip.Prefix, 0, len(peer.AllowedIPs))
	for _, n := range peer.AllowedIPs {
		addr, ok := netip.AddrFromSlice(n.IP)
		if !ok {
			return false
		}
		ones, _ := n.Mask.Size()
		have = append(have, netip.PrefixFrom(addr.Unmap(), ones))
	}
	return sameSet(have, conf.Peer.AllowedIPs)
}

func sameSet(a, b []netip.Prefix) bool {
	if len(a) != len(b) {
		return false
	}
	for _, p := range a {
		if !slices.Contains(b, p) {
			return false
		}
	}
	return true
}
