// Package wgexit runs a WireGuard exit's interface: brings it up from its
// config, re-applies its peer, recreates it, and reports its state.
//
// The agent is the interface's only controller (ТЗ §4). There is no wg-quick
// unit behind it, so the config is not a wg-quick file in full: only the keys
// that describe the tunnel are accepted. Anything that would run commands or
// install routes on its own — PostUp, Table, DNS, FwMark — is an error, because
// it would be a second controller.
package wgexit

import (
	"bufio"
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Conf is a parsed exit config.
type Conf struct {
	PrivateKey wgtypes.Key
	// Address is the interface's IPv4 address inside the tunnel.
	Address netip.Prefix
	MTU     int
	Peer    PeerConf
}

// PeerConf is the exit's single peer.
type PeerConf struct {
	PublicKey  wgtypes.Key
	AllowedIPs []netip.Prefix
	Keepalive  time.Duration
	// Endpoint from the file is informational: the agent dials the endpoint
	// picked from the policy's list, so a hoster blocking one port does not
	// need a new file.
	Endpoint netip.AddrPort
}

// LoadConf reads and parses the config at path.
func LoadConf(path string) (Conf, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Conf{}, fmt.Errorf("read exit config: %w", err)
	}
	conf, err := ParseConf(data)
	if err != nil {
		return Conf{}, fmt.Errorf("%s: %w", path, err)
	}
	return conf, nil
}

// ParseConf parses an exit config.
func ParseConf(data []byte) (Conf, error) {
	var conf Conf
	var section string
	seen := map[string]bool{}

	sc := bufio.NewScanner(bytes.NewReader(data))
	for n := 1; sc.Scan(); n++ {
		line, _, _ := strings.Cut(sc.Text(), "#")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = line
			if seen[section] {
				return Conf{}, fmt.Errorf("line %d: %s appears twice — an exit has one interface and one peer", n, section)
			}
			seen[section] = true
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return Conf{}, fmt.Errorf("line %d: %q is not key = value", n, line)
		}
		if err := conf.set(section, strings.TrimSpace(key), strings.TrimSpace(value)); err != nil {
			return Conf{}, fmt.Errorf("line %d: %w", n, err)
		}
	}
	if err := sc.Err(); err != nil {
		return Conf{}, err
	}
	return conf, conf.validate()
}

func (c *Conf) set(section, key, value string) error {
	var err error
	switch section + key {
	case "[Interface]PrivateKey":
		c.PrivateKey, err = wgtypes.ParseKey(value)
	case "[Interface]Address":
		c.Address, err = netip.ParsePrefix(value)
		if err == nil && !c.Address.Addr().Is4() {
			err = fmt.Errorf("address %s: only a single IPv4 address is supported (ТЗ §3.5)", value)
		}
	case "[Interface]MTU":
		c.MTU, err = strconv.Atoi(value)
	case "[Peer]PublicKey":
		c.Peer.PublicKey, err = wgtypes.ParseKey(value)
	case "[Peer]Endpoint":
		c.Peer.Endpoint, err = netip.ParseAddrPort(value)
	case "[Peer]AllowedIPs":
		for item := range strings.SplitSeq(value, ",") {
			p, perr := netip.ParsePrefix(strings.TrimSpace(item))
			if perr != nil {
				return fmt.Errorf("allowed ips %q: %w", value, perr)
			}
			c.Peer.AllowedIPs = append(c.Peer.AllowedIPs, p)
		}
	case "[Peer]PersistentKeepalive":
		var seconds int
		seconds, err = strconv.Atoi(value)
		c.Peer.Keepalive = time.Duration(seconds) * time.Second
	default:
		return fmt.Errorf("%s %s is not supported: the agent is the only controller of an exit", section, key)
	}
	if err != nil {
		return fmt.Errorf("%s %s: %w", section, key, err)
	}
	return nil
}

func (c Conf) validate() error {
	var zero wgtypes.Key
	switch {
	case c.PrivateKey == zero:
		return fmt.Errorf("[Interface] PrivateKey is missing")
	case !c.Address.IsValid():
		return fmt.Errorf("[Interface] Address is missing")
	case c.MTU < 1280 || c.MTU > 1500:
		return fmt.Errorf("[Interface] MTU %d is outside 1280..1500", c.MTU)
	case c.Peer.PublicKey == zero:
		return fmt.Errorf("[Peer] PublicKey is missing")
	case len(c.Peer.AllowedIPs) == 0:
		return fmt.Errorf("[Peer] AllowedIPs is missing")
	}
	return nil
}

// Render writes the config in the subset ParseConf reads: what the agent brings
// the interface up from, and nothing a second controller could act on.
func (c Conf) Render() []byte {
	var b bytes.Buffer
	b.WriteString("# The vnm agent is the only controller of this interface: no PostUp,\n")
	b.WriteString("# Table or DNS (docs/vpn-node-manager-installer.md §2).\n")
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", c.PrivateKey)
	fmt.Fprintf(&b, "Address = %s\n", c.Address)
	fmt.Fprintf(&b, "MTU = %d\n", c.MTU)
	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", c.Peer.PublicKey)
	allowed := make([]string, 0, len(c.Peer.AllowedIPs))
	for _, p := range c.Peer.AllowedIPs {
		allowed = append(allowed, p.String())
	}
	fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(allowed, ", "))
	if c.Peer.Endpoint.IsValid() {
		fmt.Fprintf(&b, "Endpoint = %s\n", c.Peer.Endpoint)
	}
	fmt.Fprintf(&b, "PersistentKeepalive = %d\n", int(c.Peer.Keepalive/time.Second))
	return b.Bytes()
}
