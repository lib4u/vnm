package wgexit_test

import (
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/lib4u/vnm/internal/infrastructure/wgexit"
)

func confText(t *testing.T) string {
	t.Helper()
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	peer, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return "[Interface]\n" +
		"PrivateKey = " + priv.String() + "\n" +
		"Address = 172.16.0.2/32\n" +
		"MTU = 1280\n" +
		"\n[Peer]\n" +
		"PublicKey = " + peer.PublicKey().String() + "\n" +
		"AllowedIPs = 0.0.0.0/0\n" +
		"Endpoint = 162.159.192.1:2408 # as written by the installer\n" +
		"PersistentKeepalive = 25\n"
}

func TestParseConf(t *testing.T) {
	conf, err := wgexit.ParseConf([]byte(confText(t)))
	if err != nil {
		t.Fatalf("ParseConf: %v", err)
	}
	if conf.MTU != 1280 || conf.Peer.Keepalive != 25*time.Second || len(conf.Peer.AllowedIPs) != 1 {
		t.Fatalf("conf = %+v", conf)
	}
}

// Keys that would let a file act on its own are refused: the agent is the only
// controller of an exit.
func TestParseConfRejects(t *testing.T) {
	tests := map[string][2]string{
		"PostUp runs commands":     {"MTU = 1280", "MTU = 1280\nPostUp = ip rule add fwmark 51820 lookup 51820"},
		"Table installs routes":    {"MTU = 1280", "MTU = 1280\nTable = off"},
		"DNS rewrites resolv.conf": {"MTU = 1280", "MTU = 1280\nDNS = 1.1.1.1"},
		"IPv6 address":             {"Address = 172.16.0.2/32", "Address = 2606:4700::2/128"},
		"second peer":              {"PersistentKeepalive = 25", "PersistentKeepalive = 25\n[Peer]\nAllowedIPs = 0.0.0.0/0"},
		"missing private key":      {"PrivateKey", "# PrivateKey"},
		"MTU above the uplink":     {"MTU = 1280", "MTU = 9000"},
	}
	for name, repl := range tests {
		t.Run(name, func(t *testing.T) {
			text := strings.Replace(confText(t), repl[0], repl[1], 1)
			if _, err := wgexit.ParseConf([]byte(text)); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestRenderRoundTrips(t *testing.T) {
	conf, err := wgexit.ParseConf([]byte(confText(t)))
	if err != nil {
		t.Fatal(err)
	}
	again, err := wgexit.ParseConf(conf.Render())
	if err != nil {
		t.Fatalf("rendered config does not parse: %v\n%s", err, conf.Render())
	}
	if again.PrivateKey != conf.PrivateKey || again.Peer.Endpoint != conf.Peer.Endpoint || again.MTU != conf.MTU {
		t.Fatalf("round trip changed the config:\n%+v\n%+v", conf, again)
	}
}
