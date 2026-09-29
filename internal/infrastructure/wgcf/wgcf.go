// Package wgcf registers a node with Cloudflare WARP through the wgcf tool and
// writes the exit config the agent runs (docs/vpn-node-manager-installer.md §2).
//
// This is installer territory: the agent itself never learns that the exit is
// WARP. The registration protocol is wgcf's business — the tool is pinned by
// version and checksum, so a change on Cloudflare's side means bumping the pin,
// not rewriting code.
package wgcf

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/lib4u/vnm/internal/infrastructure/atomicfile"
	"github.com/lib4u/vnm/internal/infrastructure/filesum"
	"github.com/lib4u/vnm/internal/infrastructure/runner"
	"github.com/lib4u/vnm/internal/infrastructure/wgexit"
	"github.com/lib4u/vnm/internal/usecase/install"
)

// The pinned wgcf release (github.com/ViRb3/wgcf).
const (
	Version = "2.3.0"
	// linuxAMD64SHA256 is the sha256 of wgcf_2.3.0_linux_amd64 from the
	// release's checksums.txt.
	linuxAMD64SHA256 = "01614e38c0eb5f3405232e71cfaf02d64d4809e4988ad8f5a8071af16d193405"
)

// Endpoint facts of the WARP service.
const (
	endpointHost = "engage.cloudflareclient.com"
	endpointPort = 2408
	exitMTU      = 1280
	keepalive    = 25 * time.Second
)

// registerBackoff is the pause before each retry of a registration: Cloudflare
// answers 5xx from time to time.
var registerBackoff = []time.Duration{10 * time.Second, 30 * time.Second, 60 * time.Second}

// ErrChecksum means the downloaded wgcf is not the pinned build.
var ErrChecksum = errors.New("wgcf checksum mismatch")

var _ install.Warp = (*Warp)(nil)

// Warp is a node's WARP registration and exit config.
type Warp struct {
	run    runner.Runner
	client *http.Client
	// Bin is where the pinned wgcf lives; Dir holds the account; Conf is the
	// exit config the agent reads.
	Bin, Dir, Conf string
	// DownloadURL and SHA256 identify the build to install; tests override
	// them.
	DownloadURL, SHA256 string
	// resolve looks the endpoint host up; tests override it.
	resolve func(ctx context.Context, host string) ([]netip.Addr, error)
	sleep   func(ctx context.Context, d time.Duration) error
}

// New returns a Warp with the pinned release.
func New(run runner.Runner, client *http.Client, bin, dir, conf string) *Warp {
	return &Warp{
		run: run, client: client, Bin: bin, Dir: dir, Conf: conf,
		DownloadURL: fmt.Sprintf("https://github.com/ViRb3/wgcf/releases/download/v%[1]s/wgcf_%[1]s_linux_amd64", Version),
		SHA256:      linuxAMD64SHA256,
		resolve: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
		},
		sleep: sleepCtx,
	}
}

func (w *Warp) account() string { return filepath.Join(w.Dir, "wgcf-account.toml") }

// license keeps the WARP+ license the operator gave: every account carries a
// license key of its own, and only this file tells a paid one from it.
func (w *Warp) license() string { return filepath.Join(w.Dir, "warp-plus.license") }

// retired is where a reissue moves the account it replaces.
func (w *Warp) retired() string { return w.account() + ".retired" }

// Registered reports whether the node already has a WARP account.
func (w *Warp) Registered() bool {
	info, err := os.Stat(w.account())
	return err == nil && info.Size() > 0
}

// EnsureTool installs the pinned wgcf unless it is already in place.
func (w *Warp) EnsureTool(ctx context.Context) error {
	if sum, err := filesum.SHA256(w.Bin); err == nil && sum == w.SHA256 {
		return nil
	}
	f, err := atomicfile.Create(w.Bin, 0o755)
	if err != nil {
		return err
	}
	defer f.Abort()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, w.DownloadURL, nil)
	if err != nil {
		return err
	}
	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("download wgcf: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download wgcf: status %s", resp.Status)
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, 64<<20)); err != nil {
		return fmt.Errorf("download wgcf: %w", err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != w.SHA256 {
		return fmt.Errorf("%w: got %s, pinned %s", ErrChecksum, got, w.SHA256)
	}
	return f.Commit()
}

// Register creates the node's WARP account, retrying Cloudflare's transient
// failures. One registration per node: a key shared between nodes makes them
// take the session from each other.
func (w *Warp) Register(ctx context.Context) error {
	if err := os.MkdirAll(w.Dir, 0o700); err != nil {
		return err
	}
	var err error
	for attempt := 0; ; attempt++ {
		// The account path goes by flag: current wgcf ignores WGCF_ACCOUNT.
		if _, err = w.wgcf(ctx, "register", "--accept-tos", "--config", w.account()); err == nil {
			return os.Chmod(w.account(), 0o600)
		}
		if attempt == len(registerBackoff) {
			return fmt.Errorf("register with WARP: %w", err)
		}
		if err := w.sleep(ctx, registerBackoff[attempt]); err != nil {
			return err
		}
	}
}

// accountType matches the account type line of `wgcf status`.
var accountType = regexp.MustCompile(`(?m)^Account type\s*:\s*(\S+)`)

// ApplyLicense upgrades the existing registration to WARP+ in place — the same
// device, keys and endpoint. It reports whether the account became unlimited.
// A license Cloudflare refuses — consumer keys are limited in devices and
// often refused for wgcf — restores the account as it was and fails with
// install.ErrLicenseNotApplied: the free account keeps working.
func (w *Warp) ApplyLicense(ctx context.Context, key string) (bool, error) {
	previous, err := os.ReadFile(w.account())
	if err != nil {
		return false, fmt.Errorf("read WARP account: %w", err)
	}
	updated, err := setLicense(previous, key)
	if err != nil {
		return false, err
	}
	if err := atomicfile.WriteFile(w.account(), updated, 0o600); err != nil {
		return false, err
	}
	if _, err := w.wgcf(ctx, "update", "--config", w.account()); err != nil {
		if rerr := atomicfile.WriteFile(w.account(), previous, 0o600); rerr != nil {
			return false, fmt.Errorf("restore WARP account after a refused license: %w", rerr)
		}
		return false, fmt.Errorf("%w: license %s: %w", install.ErrLicenseNotApplied, maskKey(key), err)
	}
	// Kept for a reissue: a new account gets the same subscription.
	if err := atomicfile.WriteFile(w.license(), []byte(key+"\n"), 0o600); err != nil {
		return false, fmt.Errorf("keep the WARP+ license: %w", err)
	}
	out, err := w.wgcf(ctx, "status", "--config", w.account())
	if err != nil {
		return false, fmt.Errorf("read WARP account status: %w", err)
	}
	m := accountType.FindStringSubmatch(out)
	return m != nil && m[1] == "unlimited", nil
}

var (
	licenseLine   = regexp.MustCompile(`(?m)^license_key\s*=.*$`)
	licenseFormat = regexp.MustCompile(`^[A-Za-z0-9]{8}-[A-Za-z0-9]{8}-[A-Za-z0-9]{8}$`)
)

func setLicense(account []byte, key string) ([]byte, error) {
	if !licenseFormat.MatchString(key) {
		return nil, fmt.Errorf("license key %s is not in the WARP+ format xxxxxxxx-xxxxxxxx-xxxxxxxx", maskKey(key))
	}
	line := []byte(fmt.Sprintf("license_key = '%s'", key))
	if licenseLine.Match(account) {
		return licenseLine.ReplaceAll(account, line), nil
	}
	return append(append(account, '\n'), line...), nil
}

// maskKey shows enough of a license key to tell keys apart, never the key: it
// is a paid credential and lands in logs. A short string — a mistyped key —
// is masked whole, or the ends would give most of it away.
func maskKey(key string) string {
	const shown = 4
	if len(key) < 6*shown {
		return strings.Repeat("*", len(key))
	}
	return key[:shown] + strings.Repeat("*", len(key)-2*shown) + key[len(key)-shown:]
}

// WriteExitConf generates the WireGuard profile and writes the strict exit
// config from it: IPv4 only, the endpoint as an address rather than a name —
// bringing the exit up after a reboot must not depend on DNS — and nothing that
// could act on its own.
// License returns the WARP+ license applied to this node, "" when none was.
func (w *Warp) License() (string, error) {
	data, err := os.ReadFile(w.license())
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read the WARP+ license: %w", err)
	}
	return strings.TrimSpace(string(data)), nil
}

// Retire moves the account aside so that the next Register creates a new
// one. restore puts it back, for when the new registration fails: a node is
// better off with a broken account than with none.
func (w *Warp) Retire(context.Context) (restore func() error, err error) {
	if err := os.Rename(w.account(), w.retired()); err != nil {
		return nil, fmt.Errorf("retire the WARP account: %w", err)
	}
	return func() error { return os.Rename(w.retired(), w.account()) }, nil
}

func (w *Warp) WriteExitConf(ctx context.Context) error {
	tmp, err := os.MkdirTemp("", "vnm-wgcf-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp) // the profile holds the private key
	profile := filepath.Join(tmp, "profile.conf")
	if _, err := w.wgcf(ctx, "generate", "--config", w.account(), "--profile", profile); err != nil {
		return fmt.Errorf("generate WARP profile: %w", err)
	}
	data, err := os.ReadFile(profile)
	if err != nil {
		return err
	}
	p, err := ParseProfile(data)
	if err != nil {
		return err
	}
	addrs, err := w.resolve(ctx, endpointHost)
	if err != nil || len(addrs) == 0 {
		return fmt.Errorf("resolve %s: %w", endpointHost, err)
	}
	conf, err := p.ExitConf(netip.AddrPortFrom(addrs[0], endpointPort))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(w.Conf), 0o700); err != nil {
		return err
	}
	return atomicfile.WriteFile(w.Conf, conf.Render(), 0o600)
}

// Profile is what the exit needs from a wgcf-generated profile.
type Profile struct {
	PrivateKey    wgtypes.Key
	PeerPublicKey wgtypes.Key
	Addresses     []netip.Prefix
}

// ParseProfile reads a wgcf profile. It is a full wg-quick file — DNS, IPv6,
// ::/0 — and is read leniently: only the keys and addresses are taken.
func ParseProfile(data []byte) (Profile, error) {
	var p Profile
	var section string
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "[") {
			section = line
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		var err error
		switch section + key {
		case "[Interface]PrivateKey":
			p.PrivateKey, err = wgtypes.ParseKey(value)
		case "[Peer]PublicKey":
			p.PeerPublicKey, err = wgtypes.ParseKey(value)
		case "[Interface]Address":
			for item := range strings.SplitSeq(value, ",") {
				prefix, perr := netip.ParsePrefix(strings.TrimSpace(item))
				if perr != nil {
					return Profile{}, fmt.Errorf("profile address %q: %w", item, perr)
				}
				p.Addresses = append(p.Addresses, prefix)
			}
		}
		if err != nil {
			return Profile{}, fmt.Errorf("profile %s: %w", key, err)
		}
	}
	return p, sc.Err()
}

// ExitConf is the strict exit config of the profile at endpoint.
func (p Profile) ExitConf(endpoint netip.AddrPort) (wgexit.Conf, error) {
	var zero wgtypes.Key
	if p.PrivateKey == zero || p.PeerPublicKey == zero {
		return wgexit.Conf{}, errors.New("profile lacks a key")
	}
	for _, a := range p.Addresses {
		if a.Addr().Is4() {
			return wgexit.Conf{
				PrivateKey: p.PrivateKey,
				Address:    a,
				MTU:        exitMTU,
				Peer: wgexit.PeerConf{
					PublicKey:  p.PeerPublicKey,
					AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
					Keepalive:  keepalive,
					Endpoint:   endpoint,
				},
			}, nil
		}
	}
	return wgexit.Conf{}, errors.New("profile has no IPv4 address")
}

func (w *Warp) wgcf(ctx context.Context, args ...string) (string, error) {
	return w.run.Run(ctx, runner.Command{Name: w.Bin, Args: args})
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
