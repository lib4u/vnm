package listcache_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lib4u/vnm/internal/domain/policy"
	"github.com/lib4u/vnm/internal/infrastructure/listcache"
)

// server publishes files and their .sha256sum companions; the checksum can be
// overridden to simulate a torn or tampered download.
type server struct {
	mu       sync.Mutex
	files    map[string]string
	override map[string]string
	// bodies counts full responses: a conditional request answered 304
	// sends none.
	bodies int
	// chunked sends bodies without a Content-Length.
	chunked bool
}

func (s *server) set(name, body string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.files[name] = body
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	name, isSum := strings.CutSuffix(r.URL.Path, ".sha256sum")
	body, ok := s.files[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	if !isSum {
		sum := sha256.Sum256([]byte(body))
		etag := `"` + hex.EncodeToString(sum[:8]) + `"`
		w.Header().Set("ETag", etag)
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		s.bodies++
		if s.chunked && len(body) > 1 {
			// A flush before the end drops the Content-Length.
			_, _ = w.Write([]byte(body[:1]))
			w.(http.Flusher).Flush()
			body = body[1:]
		}
		_, _ = w.Write([]byte(body))
		return
	}
	sum := sha256.Sum256([]byte(body))
	hexSum := hex.EncodeToString(sum[:])
	if o, ok := s.override[name]; ok {
		hexSum = o
	}
	_, _ = w.Write([]byte(hexSum + "  " + strings.TrimPrefix(name, "/") + "\n"))
}

func setup(t *testing.T) (*server, *httptest.Server, *listcache.Cache) {
	t.Helper()
	srv, ts, cache, _ := setupDir(t)
	return srv, ts, cache
}

// setupDir is setup that also returns the cache's directory.
func setupDir(t *testing.T) (*server, *httptest.Server, *listcache.Cache, string) {
	t.Helper()
	srv := &server{files: map[string]string{}, override: map[string]string{}}
	ts := httptest.NewTLSServer(srv)
	t.Cleanup(ts.Close)
	dir := t.TempDir()
	return srv, ts, listcache.New(dir, ts.Client()), dir
}

func urlSource(u string) policy.Source { return policy.Source{Kind: policy.SourceURL, Value: u} }

// checked is a list verified by its published checksum; unchecked, one that
// publishes none.
func checked(u string) policy.RemoteSource {
	return policy.RemoteSource{URL: u, Format: policy.FormatRanges}
}

func unchecked(u string) policy.RemoteSource {
	return policy.RemoteSource{URL: u, Format: policy.FormatRanges, Checksum: policy.ChecksumNone}
}

func TestRefreshThenRead(t *testing.T) {
	srv, ts, cache := setup(t)
	srv.set("/ru.txt", "# RU extra\n5.8.0.0/19\n\n77.88.55.88 # a host\n")
	u := ts.URL + "/ru.txt"

	if _, err := cache.Addresses(context.Background(), urlSource(u), policy.GeoFiles{}); !errors.Is(err, listcache.ErrNotCached) {
		t.Fatalf("before refresh: want ErrNotCached, got %v", err)
	}
	if err := cache.Refresh(context.Background(), checked(u)); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	got, err := cache.Addresses(context.Background(), urlSource(u), policy.GeoFiles{})
	if err != nil {
		t.Fatalf("Addresses: %v", err)
	}
	want := []netip.Prefix{netip.MustParsePrefix("5.8.0.0/19"), netip.MustParsePrefix("77.88.55.88/32")}
	if !slices.Equal(got, want) {
		t.Fatalf("Addresses = %v, want %v", got, want)
	}
}

// A download that does not match its checksum never replaces the good copy.
func TestChecksumMismatchKeepsPreviousCopy(t *testing.T) {
	srv, ts, cache := setup(t)
	u := ts.URL + "/ru.txt"
	srv.set("/ru.txt", "5.8.0.0/19\n")
	if err := cache.Refresh(context.Background(), checked(u)); err != nil {
		t.Fatal(err)
	}

	srv.set("/ru.txt", "<html>502 Bad Gateway</html>")
	srv.override["/ru.txt"] = strings.Repeat("ab", 32)
	if err := cache.Refresh(context.Background(), checked(u)); !errors.Is(err, listcache.ErrChecksum) {
		t.Fatalf("want ErrChecksum, got %v", err)
	}
	got, err := cache.Addresses(context.Background(), urlSource(u), policy.GeoFiles{})
	if err != nil || !slices.Equal(got, []netip.Prefix{netip.MustParsePrefix("5.8.0.0/19")}) {
		t.Fatalf("previous copy lost: %v %v", got, err)
	}
}

func TestMissingChecksumIsAnError(t *testing.T) {
	_, ts, cache := setup(t)
	if err := cache.Refresh(context.Background(), checked(ts.URL+"/absent.txt")); err == nil {
		t.Fatal("a file without a published checksum was accepted")
	}
}

func TestFileSourceRejectsGarbage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "list.txt")
	if err := os.WriteFile(path, []byte("5.8.0.0/19\nnot-an-address\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	src := policy.Source{Kind: policy.SourceFile, Value: path}
	if _, err := listcache.New(t.TempDir(), nil).Addresses(context.Background(), src, policy.GeoFiles{}); err == nil {
		t.Fatal("a list with a garbage line was accepted")
	}
}

// Without a checksum a copy is kept only if it parses as a whole: an error
// page, a torn line or an empty file never replaces the good copy.
func TestUncheckedKeepsOnlyParsableCopies(t *testing.T) {
	srv, ts, cache := setup(t)
	u := ts.URL + "/scanners.list"
	srv.set("/scanners.list", "# AS61280\n185.224.228.0/24\n2001:db8::/32\n")
	if err := cache.Refresh(context.Background(), unchecked(u)); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	for _, broken := range []string{"<html>429 Too Many Requests</html>", "185.224.228.0/24\n185.22", "# nothing\n"} {
		srv.set("/scanners.list", broken)
		if err := cache.Refresh(context.Background(), unchecked(u)); !errors.Is(err, listcache.ErrUnparsable) {
			t.Fatalf("%q: want ErrUnparsable, got %v", broken, err)
		}
	}
	got, err := cache.Addresses(context.Background(), urlSource(u), policy.GeoFiles{})
	if err != nil || len(got) != 2 {
		t.Fatalf("previous copy lost: %v %v", got, err)
	}
}

// An unchanged file is confirmed by its ETag, not sent again — and still
// counts as verified, while its content keeps the time it changed.
func TestUncheckedConditionalRequest(t *testing.T) {
	srv, ts, cache := setup(t)
	u := ts.URL + "/scanners.list"
	srv.set("/scanners.list", "185.224.228.0/24\n")
	if err := cache.Refresh(context.Background(), unchecked(u)); err != nil {
		t.Fatal(err)
	}
	first, err := cache.Times(u)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	if err := cache.Refresh(context.Background(), unchecked(u)); err != nil {
		t.Fatal(err)
	}
	second, _ := cache.Times(u)
	if srv.bodies != 1 || !second.Verified.After(first.Verified) || !second.Modified.Equal(first.Modified) {
		t.Fatalf("bodies %d, times %+v → %+v", srv.bodies, first, second)
	}

	srv.set("/scanners.list", "185.224.229.0/24\n")
	if err := cache.Refresh(context.Background(), unchecked(u)); err != nil || srv.bodies != 2 {
		t.Fatalf("changed file: %v, bodies %d", err, srv.bodies)
	}
	if third, _ := cache.Times(u); !third.Modified.After(first.Modified) {
		t.Fatalf("a changed copy kept its time: %+v", third)
	}
}

// A confirmation by checksum does not touch the copy either.
func TestChecksumConfirmationKeepsModified(t *testing.T) {
	srv, ts, cache := setup(t)
	u := ts.URL + "/ru.txt"
	srv.set("/ru.txt", "5.8.0.0/19\n")
	if err := cache.Refresh(context.Background(), checked(u)); err != nil {
		t.Fatal(err)
	}
	first, _ := cache.Times(u)
	time.Sleep(10 * time.Millisecond)
	if err := cache.Refresh(context.Background(), checked(u)); err != nil {
		t.Fatal(err)
	}
	if second, _ := cache.Times(u); !second.Verified.After(first.Verified) || !second.Modified.Equal(first.Modified) {
		t.Fatalf("times %+v → %+v", first, second)
	}
}

// An ETag stored for other content than the copy's — two refreshes crossing
// — is not sent: a 304 would confirm a copy the server never sent for it.
func TestUncheckedIgnoresETagOfOtherContent(t *testing.T) {
	srv, ts, cache, dir := setupDir(t)
	u := ts.URL + "/scanners.list"
	srv.set("/scanners.list", "185.224.228.0/24\n")
	if err := cache.Refresh(context.Background(), unchecked(u)); err != nil {
		t.Fatal(err)
	}
	copies, err := filepath.Glob(filepath.Join(dir, "*-scanners.list"))
	if err != nil || len(copies) != 1 {
		t.Fatalf("copies %v, %v", copies, err)
	}
	if err := os.WriteFile(copies[0], []byte("192.0.2.0/24\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cache.Refresh(context.Background(), unchecked(u)); err != nil || srv.bodies != 2 {
		t.Fatalf("refresh: %v, bodies %d — the stale pairing was confirmed", err, srv.bodies)
	}
	got, err := cache.Addresses(context.Background(), urlSource(u), policy.GeoFiles{})
	if err != nil || !slices.Equal(got, []netip.Prefix{netip.MustParsePrefix("185.224.228.0/24")}) {
		t.Fatalf("copy = %v, %v", got, err)
	}
}

// twoServers returns a cache whose client trusts both test servers, and the
// two: from the first, paths redirect to the same path on the second.
func twoServers(t *testing.T) (*server, *httptest.Server, *listcache.Cache) {
	t.Helper()
	otherSrv, other, _ := setup(t)
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusFound)
	}))
	t.Cleanup(ts.Close)
	client := ts.Client()
	client.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = true // two test servers, two certificates
	return otherSrv, ts, listcache.New(t.TempDir(), client)
}

// Nobody but the named host vouches for an unchecked file.
func TestUncheckedRefusesCrossHostRedirect(t *testing.T) {
	otherSrv, ts, cache := twoServers(t)
	otherSrv.set("/scanners.list", "185.224.228.0/24\n")
	err := cache.Refresh(context.Background(), unchecked(ts.URL+"/scanners.list"))
	if err == nil || !strings.Contains(err.Error(), "another host") {
		t.Fatalf("a redirect to another host was followed: %v", err)
	}
}

// A checked file may move to another host — the geo releases do — since its
// checksum vouches for it.
func TestCheckedFollowsCrossHostRedirect(t *testing.T) {
	otherSrv, ts, cache := twoServers(t)
	otherSrv.set("/geoip.dat", "5.8.0.0/19\n")
	if err := cache.Refresh(context.Background(), checked(ts.URL+"/geoip.dat")); err != nil {
		t.Fatalf("a checked file behind a redirect: %v", err)
	}
}

// No hop may leave https, whatever vouches for the file.
func TestRefusesRedirectToPlainHTTP(t *testing.T) {
	plain := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(plain.Close)
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+r.URL.Path, http.StatusFound)
	}))
	t.Cleanup(ts.Close)
	cache := listcache.New(t.TempDir(), ts.Client())
	for _, src := range []policy.RemoteSource{checked(ts.URL + "/ru.txt"), unchecked(ts.URL + "/ru.txt")} {
		err := cache.Refresh(context.Background(), src)
		if err == nil || !strings.Contains(err.Error(), "not https") {
			t.Fatalf("checksum %d: a redirect to plain http was followed: %v", src.Checksum, err)
		}
	}
}

// A copy's temporary files left by a crash are removed by the next refresh;
// one being written is left alone.
func TestRefreshRemovesStaleTemps(t *testing.T) {
	srv, ts, cache, dir := setupDir(t)
	srv.set("/ru.txt", "5.8.0.0/19\n")
	stale := filepath.Join(dir, ".0123456789abcdef-ru.txt.1234")
	live := filepath.Join(dir, ".0123456789abcdef-ru.txt.5678")
	for _, name := range []string{stale, live} {
		if err := os.WriteFile(name, []byte("5.8"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatal(err)
	}
	if err := cache.Refresh(context.Background(), checked(ts.URL+"/ru.txt")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale temporary file: %v", err)
	}
	if _, err := os.Stat(live); err != nil {
		t.Fatalf("live temporary file: %v", err)
	}
}

// A last line without a newline is accepted when the transfer proved itself
// complete — real lists lack it — and refused otherwise: one cut off inside
// it may still parse, "…/24" arriving as "…/2".
func TestUncheckedUnterminatedLastLine(t *testing.T) {
	srv, ts, cache := setup(t)
	u := unchecked(ts.URL + "/scanners.list")
	srv.set("/scanners.list", "185.224.228.0/24\n10.0.0.0/24")
	if err := cache.Refresh(context.Background(), u); err != nil {
		t.Fatalf("a whole transfer without a final newline: %v", err)
	}

	srv.mu.Lock()
	srv.chunked = true
	srv.mu.Unlock()
	srv.set("/scanners.list", "185.224.228.0/24\n10.0.0.0/2")
	if err := cache.Refresh(context.Background(), u); !errors.Is(err, listcache.ErrUnparsable) {
		t.Fatalf("an unterminated line of unknown length: want ErrUnparsable, got %v", err)
	}
}

func TestTimesAndFiles(t *testing.T) {
	cache := listcache.New(t.TempDir(), nil)
	if _, err := cache.Times("https://lists.example.test/absent.list"); !errors.Is(err, listcache.ErrNotCached) {
		t.Fatalf("Times of a copy never downloaded: %v", err)
	}
	path := filepath.Join(t.TempDir(), "manual.list")
	if _, err := cache.FileModified(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("FileModified of an absent file: %v", err)
	}
	if err := os.WriteFile(path, []byte("192.0.2.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if got, err := cache.FileModified(path); err != nil || !got.Equal(info.ModTime()) {
		t.Fatalf("FileModified = %v, %v", got, err)
	}
}
