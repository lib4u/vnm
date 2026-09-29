package wgcf

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/lib4u/vnm/internal/infrastructure/runner"
	"github.com/lib4u/vnm/internal/infrastructure/wgexit"
	"github.com/lib4u/vnm/internal/usecase/install"
)

// fakeRunner answers wgcf invocations through a function.
type fakeRunner struct {
	calls []string
	do    func(args []string) (string, error)
}

func (f *fakeRunner) Run(_ context.Context, cmd runner.Command) (string, error) {
	f.calls = append(f.calls, strings.Join(cmd.Args, " "))
	return f.do(cmd.Args)
}

func newWarp(t *testing.T, r runner.Runner) *Warp {
	t.Helper()
	dir := t.TempDir()
	w := New(r, nil, filepath.Join(dir, "bin", "wgcf"), filepath.Join(dir, "warp"), filepath.Join(dir, "warp", "warp.conf"))
	w.sleep = func(context.Context, time.Duration) error { return nil }
	w.resolve = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("162.159.192.1")}, nil
	}
	return w
}

func profileText(t *testing.T) string {
	t.Helper()
	priv, _ := wgtypes.GeneratePrivateKey()
	peer, _ := wgtypes.GeneratePrivateKey()
	return "[Interface]\nPrivateKey = " + priv.String() + "\n" +
		"Address = 172.16.0.2/32, 2606:4700:110:85da::1bc/128\nDNS = 1.1.1.1\nMTU = 1280\n\n" +
		"[Peer]\nPublicKey = " + peer.PublicKey().String() + "\n" +
		"AllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = engage.cloudflareclient.com:2408\n"
}

// The wgcf profile is a full wg-quick file; the exit config keeps only what the
// agent runs, with the endpoint as an address.
func TestWriteExitConf(t *testing.T) {
	profile := profileText(t)
	r := &fakeRunner{do: func(args []string) (string, error) {
		if args[0] == "generate" {
			return "", os.WriteFile(args[len(args)-1], []byte(profile), 0o600)
		}
		return "", nil
	}}
	w := newWarp(t, r)
	if err := w.WriteExitConf(context.Background()); err != nil {
		t.Fatalf("WriteExitConf: %v", err)
	}
	conf, err := wgexit.LoadConf(w.Conf)
	if err != nil {
		t.Fatalf("written config does not pass the agent's parser: %v", err)
	}
	if conf.Address.String() != "172.16.0.2/32" || conf.Peer.Endpoint.String() != "162.159.192.1:2408" || len(conf.Peer.AllowedIPs) != 1 {
		t.Fatalf("conf = %+v", conf)
	}
	info, _ := os.Stat(w.Conf)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("exit config mode %v: it holds the private key", info.Mode())
	}
}

func TestRegisterRetriesTransientFailures(t *testing.T) {
	attempts := 0
	var w *Warp
	r := &fakeRunner{do: func([]string) (string, error) {
		attempts++
		if attempts < 3 {
			return "", errors.New("500 Internal Server Error")
		}
		return "", os.WriteFile(w.account(), []byte("device_id = 'x'\n"), 0o644)
	}}
	w = newWarp(t, r)
	if err := w.Register(context.Background()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if attempts != 3 || !w.Registered() {
		t.Fatalf("attempts %d, registered %t", attempts, w.Registered())
	}
	if !strings.Contains(r.calls[0], "--accept-tos --config") {
		t.Fatalf("register call %q: the account goes by --config, wgcf ignores WGCF_ACCOUNT", r.calls[0])
	}
	info, _ := os.Stat(w.account())
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("account mode %v: it holds the access token", info.Mode())
	}
}

func TestRegisterGivesUp(t *testing.T) {
	r := &fakeRunner{do: func([]string) (string, error) { return "", errors.New("500") }}
	if err := newWarp(t, r).Register(context.Background()); err == nil {
		t.Fatal("a registration that never succeeds was reported as done")
	}
	if len(r.calls) != len(registerBackoff)+1 {
		t.Fatalf("attempts = %d", len(r.calls))
	}
}

func TestSetLicense(t *testing.T) {
	account := []byte("access_token = 'a'\nlicense_key = 'old'\n")
	got, err := setLicense(account, "1a2b3c4d-5e6f7g8h-9i0j1k2l")
	if err != nil || !strings.Contains(string(got), "license_key = '1a2b3c4d-5e6f7g8h-9i0j1k2l'") || strings.Contains(string(got), "old") {
		t.Fatalf("setLicense = %q, %v", got, err)
	}
	if _, err := setLicense(account, "not-a-key"); err == nil {
		t.Fatal("malformed key accepted")
	}
}

func TestApplyLicenseReportsAccountType(t *testing.T) {
	var w *Warp
	r := &fakeRunner{do: func(args []string) (string, error) {
		if args[0] == "status" {
			return "Account type      : unlimited\n", nil
		}
		return "", nil
	}}
	w = newWarp(t, r)
	if err := os.MkdirAll(w.Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(w.account(), []byte("license_key = 'x'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	plus, err := w.ApplyLicense(context.Background(), "1a2b3c4d-5e6f7g8h-9i0j1k2l")
	if err != nil || !plus {
		t.Fatalf("ApplyLicense = %t, %v", plus, err)
	}
	if !slices.Contains(r.calls, "update --config "+w.account()) {
		t.Fatalf("calls = %v: the license goes onto the same device, no new registration", r.calls)
	}
	// Kept for a reissue.
	if got, err := w.License(); err != nil || got != "1a2b3c4d-5e6f7g8h-9i0j1k2l" {
		t.Fatalf("License = %q, %v", got, err)
	}
}

// A license Cloudflare refuses leaves the account as it was — no bad key in
// it — and the error never shows the key.
func TestApplyLicenseRefusedRestoresAccount(t *testing.T) {
	const key = "1a2b3c4d-5e6f7g8h-9i0j1k2l"
	r := &fakeRunner{do: func(args []string) (string, error) {
		if args[0] == "update" {
			return "", errors.New("403 Forbidden")
		}
		return "", nil
	}}
	w := newWarp(t, r)
	if err := os.MkdirAll(w.Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	account := []byte("access_token = 'a'\nlicense_key = 'free0000-free0000-free0000'\n")
	if err := os.WriteFile(w.account(), account, 0o600); err != nil {
		t.Fatal(err)
	}
	plus, err := w.ApplyLicense(context.Background(), key)
	if plus || !errors.Is(err, install.ErrLicenseNotApplied) {
		t.Fatalf("ApplyLicense = %t, %v", plus, err)
	}
	if strings.Contains(err.Error(), key) {
		t.Fatalf("error shows the key: %v", err)
	}
	if got, _ := os.ReadFile(w.account()); string(got) != string(account) {
		t.Fatalf("account not restored:\n%s", got)
	}
	if got, _ := w.License(); got != "" {
		t.Fatalf("a refused license was kept: %q", got)
	}
}

// Retire moves the account aside for a new registration and puts it back on
// demand; without a license file there is no WARP+ to carry over.
func TestRetireAndRestore(t *testing.T) {
	w := newWarp(t, &fakeRunner{do: func([]string) (string, error) { return "", nil }})
	if err := os.MkdirAll(w.Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(w.account(), []byte("access_token = 'old'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := w.License(); err != nil || got != "" {
		t.Fatalf("License = %q, %v", got, err)
	}
	restore, err := w.Retire(context.Background())
	if err != nil || w.Registered() {
		t.Fatalf("Retire: %v, registered %t", err, w.Registered())
	}
	if err := restore(); err != nil || !w.Registered() {
		t.Fatalf("restore: %v, registered %t", err, w.Registered())
	}
}

func TestMaskKey(t *testing.T) {
	for key, want := range map[string]string{
		"1a2b3c4d-5e6f7g8h-9i0j1k2l": "1a2b******************1k2l",
		"not-a-key":                  "*********",
	} {
		if got := maskKey(key); got != want {
			t.Errorf("maskKey(%q) = %q, want %q", key, got, want)
		}
	}
}

// Only the pinned build is installed; anything else leaves no binary behind.
func TestEnsureToolVerifiesChecksum(t *testing.T) {
	good := []byte("#!/bin/sh\necho wgcf\n")
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(good) }))
	defer srv.Close()
	sum := sha256.Sum256(good)

	w := newWarp(t, nil)
	w.client, w.DownloadURL = srv.Client(), srv.URL
	w.SHA256 = strings.Repeat("0", 64)
	if err := w.EnsureTool(context.Background()); !errors.Is(err, ErrChecksum) {
		t.Fatalf("want ErrChecksum, got %v", err)
	}
	if _, err := os.Stat(w.Bin); !os.IsNotExist(err) {
		t.Fatal("a build with the wrong checksum was installed")
	}

	w.SHA256 = hex.EncodeToString(sum[:])
	if err := w.EnsureTool(context.Background()); err != nil {
		t.Fatalf("EnsureTool: %v", err)
	}
	info, err := os.Stat(w.Bin)
	if err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("installed tool: %v %v", info, err)
	}
}
