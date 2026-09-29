package lists_test

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/lib4u/vnm/internal/domain/policy"
	"github.com/lib4u/vnm/internal/testsupport"
	"github.com/lib4u/vnm/internal/usecase/lists"
)

// source serves fixed ranges per source value.
type source map[string][]netip.Prefix

func (s source) Domains(_ context.Context, src policy.Source, _ policy.GeoFiles) ([]string, error) {
	switch src.Value {
	case "category-ru":
		return []string{"VK.com", "gosuslugi.ru.", "vk.com"}, nil
	case "category-empty":
		return nil, nil
	case "category-evil":
		return []string{"x\nserver=6.6.6.6"}, nil
	}
	return nil, fmt.Errorf("no domains for %q", src.Value)
}

func (s source) Addresses(_ context.Context, src policy.Source, _ policy.GeoFiles) ([]netip.Prefix, error) {
	got, ok := s[src.Value]
	if !ok {
		return nil, fmt.Errorf("no data for %q", src.Value)
	}
	return got, nil
}

// ranges returns n distinct /32s.
func ranges(n int) []netip.Prefix {
	out := make([]netip.Prefix, 0, n)
	addr := netip.MustParseAddr("198.18.0.0")
	for range n {
		out = append(out, netip.PrefixFrom(addr, 32))
		addr = addr.Next()
	}
	return out
}

// ranges6 returns n distinct /128s.
func ranges6(n int) []netip.Prefix {
	out := make([]netip.Prefix, 0, n)
	addr := netip.MustParseAddr("2001:db8::")
	for range n {
		out = append(out, netip.PrefixFrom(addr, 128))
		addr = addr.Next()
	}
	return out
}

func config(bounds policy.Bounds) policy.Config {
	cfg := testsupport.Policy()
	cfg.Lists[0].Bounds = bounds
	cfg.Lists[0].ExtraCIDR = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
	return cfg
}

func TestResolveMergesSourcesAndExtras(t *testing.T) {
	r := lists.NewResolver(source{"ru": ranges(3)})
	got, err := r.Resolve(context.Background(), config(policy.DefaultBounds), nil)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(got.Ranges["ru_ip"]) != 4 {
		t.Fatalf("ru_ip = %v, want 3 source ranges + 1 extra", got.Ranges["ru_ip"])
	}
	if _, ok := got.Ranges["ru_suffix"]; ok {
		t.Fatal("a domain-only list resolved to address ranges")
	}
}

// A guard list fails alone; an egress list fails everything (G-4, I-1).
func TestResolveGuardListFailsAlone(t *testing.T) {
	cfg := config(policy.DefaultBounds)
	cfg.Lists[2].IP = []policy.Source{{Kind: policy.SourceURL, Value: "https://lists.example.test/scanners.list"}}
	got, err := lists.NewResolver(source{"ru": ranges(3)}).Resolve(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("a guard list failed the resolution: %v", err)
	}
	if got.Failed["scanners"] == nil || len(got.Ranges["ru_ip"]) != 4 {
		t.Fatalf("resolved %+v", got)
	}

	// The same list used by the egress too is strict.
	cfg.Rules[0].Lists = append(cfg.Rules[0].Lists, "scanners")
	if _, err := lists.NewResolver(source{"ru": ranges(3)}).Resolve(context.Background(), cfg, nil); err == nil {
		t.Fatal("an egress list failed without failing the resolution")
	}
}

// Only the lists an active part applies are read.
func TestResolveOnlyActiveLists(t *testing.T) {
	cfg := config(policy.DefaultBounds)
	cfg.Mode = policy.ModeOff
	got, err := lists.NewResolver(source{}).Resolve(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("an egress list was read with the egress off: %v", err)
	}
	if _, ok := got.Ranges["scanners"]; !ok || len(got.Ranges) != 1 {
		t.Fatalf("resolved %+v", got.Ranges)
	}
}

func TestResolveBounds(t *testing.T) {
	bounds := policy.Bounds{Min: 5, Max: 100, MaxChange: 0.5}
	tests := []struct {
		name     string
		size     int
		previous int
		wantErr  bool
	}{
		{"within bounds, new list", 20, 0, false},
		{"too few — a file that lost its content", 3, 0, true},
		{"too many", 200, 0, true},
		{"normal growth", 26, 20, false},
		{"collapse against the applied list", 8, 20, true},
		{"explosion against the applied list", 50, 20, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// One extra range is always added by config().
			r := lists.NewResolver(source{"ru": ranges(tt.size - 1)})
			_, err := r.Resolve(context.Background(), config(bounds), map[string]lists.Sizes{"ru_ip": {V4: tt.previous}})
			if tt.wantErr != errors.Is(err, lists.ErrOutOfBounds) {
				t.Fatalf("err = %v, want out-of-bounds %t", err, tt.wantErr)
			}
		})
	}
}

// The largest change holds per family: a list that lost its IPv4 ranges has
// not stayed the same because its IPv6 ones grew as much.
func TestResolveBoundsPerFamily(t *testing.T) {
	bounds := policy.Bounds{Min: 5, Max: 100, MaxChange: 0.5}
	previous := map[string]lists.Sizes{"ru_ip": {V4: 10, V6: 10}}
	resolve := func(v4, v6 int) error {
		r := lists.NewResolver(source{"ru": slices.Concat(ranges(v4), ranges6(v6))})
		_, err := r.Resolve(context.Background(), config(bounds), previous)
		return err
	}
	// One extra IPv4 range is always added by config().
	if err := resolve(10, 12); err != nil {
		t.Fatalf("normal change refused: %v", err)
	}
	if err := resolve(0, 19); !errors.Is(err, lists.ErrOutOfBounds) {
		t.Fatalf("IPv4 collapse under a stable total: err = %v, want out-of-bounds", err)
	}

	// A family the applied list did not have is new, not an explosion.
	previous["ru_ip"] = lists.Sizes{V4: 10}
	if err := resolve(9, 4); err != nil {
		t.Fatalf("a new family refused: %v", err)
	}
}

// A source without entries fails its list: the list must not live on its
// extras alone.
func TestResolveEmptySource(t *testing.T) {
	_, err := lists.NewResolver(source{"ru": nil}).Resolve(context.Background(), config(policy.DefaultBounds), nil)
	if !errors.Is(err, lists.ErrEmptySource) {
		t.Fatalf("err = %v, want ErrEmptySource", err)
	}
}

func TestResolveFailsWhole(t *testing.T) {
	r := lists.NewResolver(source{})
	if _, err := r.Resolve(context.Background(), config(policy.DefaultBounds), nil); err == nil {
		t.Fatal("a missing source did not fail the resolution")
	}
}

// downloader records refreshes and fails on demand.
type downloader struct {
	got      []string
	fail     string
	updated  map[string]time.Time
	modified map[string]time.Time
	// broken copies cannot be read; files are the local files that exist.
	broken map[string]error
	files  map[string]time.Time
}

func (d *downloader) Times(url string) (lists.Times, error) {
	if err, ok := d.broken[url]; ok {
		return lists.Times{}, err
	}
	t, ok := d.updated[url]
	if !ok {
		return lists.Times{}, fmt.Errorf("%w: %s", lists.ErrNotCached, url)
	}
	return lists.Times{Verified: t, Modified: d.modified[url]}, nil
}

func (d *downloader) FileModified(path string) (time.Time, error) {
	t, ok := d.files[path]
	if !ok {
		return time.Time{}, fmt.Errorf("stat %s: %w", path, fs.ErrNotExist)
	}
	return t, nil
}

func (d *downloader) Refresh(_ context.Context, src policy.RemoteSource) error {
	d.got = append(d.got, src.URL)
	if src.URL == d.fail {
		return errors.New("unreachable")
	}
	return nil
}

var now = time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)

func clock() time.Time { return now }

func TestRefreshFetchesEachRemoteOnceAndContinuesPastFailures(t *testing.T) {
	cfg := testsupport.Policy()
	cfg.Lists = append(cfg.Lists,
		policy.List{Name: "more", IP: []policy.Source{{Kind: policy.SourceGeoIP, Value: "by"}}, Bounds: policy.DefaultBounds},
		policy.List{Name: "extra", IP: []policy.Source{{Kind: policy.SourceURL, Value: "https://example.org/ru.txt"}}, Bounds: policy.DefaultBounds},
	)
	dl := &downloader{fail: cfg.Geo.GeoIP}

	err := lists.NewRemote(dl, clock, 0).Refresh(context.Background(), cfg)
	if err == nil {
		t.Fatal("a failed download was not reported")
	}
	want := []string{cfg.Geo.GeoIP, "https://example.org/ru.txt"}
	if !slices.Equal(dl.got, want) {
		t.Fatalf("refreshed %v, want %v (each once, the rest after the failure)", dl.got, want)
	}
}

// A copy is downloaded when it is missing or older than the refresh of the
// most demanding list reading it — this node's spread added.
func TestRefreshOnlyDueCopies(t *testing.T) {
	cfg := testsupport.Policy()
	fresh := "https://lists.example.test/fresh.list"
	stale := "https://lists.example.test/stale.list"
	cfg.Lists = append(cfg.Lists,
		policy.List{Name: "fresh", IP: []policy.Source{{Kind: policy.SourceURL, Value: fresh}}, Refresh: 12 * time.Hour, Bounds: policy.DefaultBounds},
		policy.List{Name: "stale", IP: []policy.Source{{Kind: policy.SourceURL, Value: stale}}, Refresh: 12 * time.Hour, Bounds: policy.DefaultBounds},
	)
	dl := &downloader{updated: map[string]time.Time{
		cfg.Geo.GeoIP: now.Add(-23 * time.Hour), // refresh 24h: not due
		fresh:         now.Add(-11 * time.Hour),
		stale:         now.Add(-13 * time.Hour),
	}}
	if err := lists.NewRemote(dl, clock, 0).Refresh(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(dl.got, []string{stale}) {
		t.Fatalf("refreshed %v, want the stale copy only", dl.got)
	}

	// The spread delays this node: 13h is not yet due at 12h + 10%.
	dl.got = nil
	if err := lists.NewRemote(dl, clock, lists.MaxSpread).Refresh(context.Background(), cfg); err != nil || len(dl.got) != 0 {
		t.Fatalf("refreshed %v, %v", dl.got, err)
	}

	// A missing copy is always due; RefreshAll takes every copy.
	delete(dl.updated, fresh)
	dl.got = nil
	if err := lists.NewRemote(dl, clock, 0).Refresh(context.Background(), cfg); err != nil || !slices.Equal(dl.got, []string{fresh, stale}) {
		t.Fatalf("refreshed %v, %v", dl.got, err)
	}
	dl.got = nil
	if err := lists.NewRemote(dl, clock, 0).RefreshAll(context.Background(), cfg); err != nil || len(dl.got) != 3 {
		t.Fatalf("refreshed all: %v, %v", dl.got, err)
	}
}

// A source that keeps failing rests before each retry, twice as long each
// time, up to its refresh; missing or not, and until a download succeeds.
func TestRefreshBacksOffAFailingSource(t *testing.T) {
	cfg := testsupport.Policy() // the geoip file, refresh 24h, never downloaded
	at := now
	dl := &downloader{fail: cfg.Geo.GeoIP}
	r := lists.NewRemote(dl, func() time.Time { return at }, 0)
	attempts := func(after time.Duration) int {
		at = at.Add(after)
		dl.got = nil
		_ = r.Refresh(context.Background(), cfg)
		return len(dl.got)
	}

	if n := attempts(0); n != 1 {
		t.Fatalf("first attempt: %d downloads", n)
	}
	for _, wait := range []time.Duration{
		10 * time.Minute, 20 * time.Minute, 40 * time.Minute, 80 * time.Minute, 160 * time.Minute,
		320 * time.Minute, 640 * time.Minute, 1280 * time.Minute, 24 * time.Hour, 24 * time.Hour,
	} {
		if n := attempts(wait - time.Minute); n != 0 {
			t.Fatalf("retried %v before the rest of %v ended", wait-time.Minute, wait)
		}
		if n := attempts(time.Minute); n != 1 {
			t.Fatalf("not retried after the rest of %v", wait)
		}
	}

	// `vnm lists update` does not wait for the rest.
	dl.got = nil
	if err := r.RefreshAll(context.Background(), cfg); err == nil || len(dl.got) != 1 {
		t.Fatalf("RefreshAll during a rest: %v, %v", dl.got, err)
	}

	// A success ends the rests: the copy, still missing, is due at once.
	dl.fail = ""
	if n := attempts(24 * time.Hour); n != 1 {
		t.Fatalf("not retried after the longest rest")
	}
	if n := attempts(0); n != 1 {
		t.Fatalf("a success did not end the rests")
	}
}

func TestCopies(t *testing.T) {
	cfg := testsupport.Policy()
	manual := "/etc/vnm/guard-manual.list"
	absent := "/etc/vnm/absent.list"
	cfg.Lists = append(cfg.Lists,
		policy.List{Name: "manual", IP: []policy.Source{{Kind: policy.SourceFile, Value: manual}}, Bounds: policy.DefaultBounds},
		policy.List{Name: "absent", IP: []policy.Source{{Kind: policy.SourceFile, Value: absent}}, Bounds: policy.DefaultBounds},
	)
	dl := &downloader{updated: map[string]time.Time{}, files: map[string]time.Time{manual: now.Add(-time.Hour)}}
	r := lists.NewRemote(dl, clock, 0)

	got := r.Copies(cfg)
	if c := got[cfg.Geo.GeoIP]; !c.Missing || c.Err != nil {
		t.Fatalf("never downloaded: %+v", c)
	}
	if c := got[lists.FileKey(manual)]; c.Missing || !c.Modified.Equal(now.Add(-time.Hour)) || !c.Updated.Equal(c.Modified) {
		t.Fatalf("local file: %+v", c)
	}
	if c := got[lists.FileKey(absent)]; !c.Missing {
		t.Fatalf("absent local file: %+v", c)
	}
	if len(got) != 3 {
		t.Fatalf("copies = %+v", got)
	}

	// A confirmation moves Updated only; a copy that cannot be read is not
	// taken for one never downloaded.
	dl.updated[cfg.Geo.GeoIP], dl.modified = now, map[string]time.Time{cfg.Geo.GeoIP: now.Add(-48 * time.Hour)}
	if c := r.Copies(cfg)[cfg.Geo.GeoIP]; c.Missing || !c.Updated.Equal(now) || !c.Modified.Equal(now.Add(-48*time.Hour)) {
		t.Fatalf("copy = %+v", c)
	}
	dl.broken = map[string]error{cfg.Geo.GeoIP: fs.ErrPermission}
	if c := r.Copies(cfg)[cfg.Geo.GeoIP]; c.Missing || !errors.Is(c.Err, fs.ErrPermission) {
		t.Fatalf("unreadable copy = %+v", c)
	}
}

func TestDomainsMergeSourcesAndZones(t *testing.T) {
	cfg := testsupport.Policy()
	cfg.Lists = append(cfg.Lists, policy.List{
		Name: "ru_domain", Domain: []policy.Source{{Kind: policy.SourceGeoSite, Value: "category-ru"}}, Bounds: policy.DefaultBounds,
	})
	cfg.Rules[0].Lists = append(cfg.Rules[0].Lists, "ru_domain")
	got, err := lists.NewResolver(source{}).Domains(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Domains: %v", err)
	}
	if want := []string{"gosuslugi.ru", "vk.com"}; !slices.Equal(got["ru_domain"], want) {
		t.Errorf("ru_domain = %v, want %v (lowercased, no trailing dot, deduplicated)", got["ru_domain"], want)
	}
	if want := []string{"ru", "xn--p1ai"}; !slices.Equal(got["ru_suffix"], want) {
		t.Errorf("ru_suffix = %v, want %v", got["ru_suffix"], want)
	}
	if _, ok := got["ru_ip"]; ok {
		t.Error("an address-only list resolved to domains")
	}
}

// Domains of a source are checked wherever they come from: nothing but a
// domain reaches the resolver's config, and a source without any fails.
func TestDomainsRejectsBadSources(t *testing.T) {
	for value, want := range map[string]error{"category-evil": nil, "category-empty": lists.ErrEmptySource} {
		cfg := testsupport.Policy()
		cfg.Lists = append(cfg.Lists, policy.List{
			Name: "ru_domain", Domain: []policy.Source{{Kind: policy.SourceGeoSite, Value: value}}, Bounds: policy.DefaultBounds,
		})
		cfg.Rules[0].Lists = append(cfg.Rules[0].Lists, "ru_domain")
		_, err := lists.NewResolver(source{}).Domains(context.Background(), cfg)
		if err == nil || want != nil && !errors.Is(err, want) {
			t.Errorf("%s: err = %v, want %v", value, err, want)
		}
	}
}
