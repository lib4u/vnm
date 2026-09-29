// Package lists turns the policy's list definitions into address ranges and
// keeps their remote sources fresh (ТЗ §7.4).
//
// Resolving and fetching are separate on purpose. Resolve reads only local
// data, so it works offline and at boot; Refresh is the only step that touches
// the network, and a failed refresh leaves the previous local copy in place.
package lists

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/lib4u/vnm/internal/domain/netstate"
	"github.com/lib4u/vnm/internal/domain/policy"
)

// Source reads the entries of one list source from local data.
type Source interface {
	Addresses(ctx context.Context, src policy.Source, geo policy.GeoFiles) ([]netip.Prefix, error)
	// Domains returns the domains a source lists, each matching itself and
	// its subdomains.
	Domains(ctx context.Context, src policy.Source, geo policy.GeoFiles) ([]string, error)
}

// ErrNotCached means a remote source has not been downloaded yet.
var ErrNotCached = errors.New("source is not downloaded yet")

// Times are the times of a local copy.
type Times struct {
	// Verified is when the copy was last verified current: downloaded, or
	// confirmed unchanged.
	Verified time.Time
	// Modified is when its content last changed. A confirmation does not
	// move it, so an unchanged copy is not read again.
	Modified time.Time
}

// Downloader keeps local copies of remote files, and tells when the local
// list files changed.
type Downloader interface {
	// Refresh updates the local copy of a source. On failure the previous
	// copy stays untouched; a download confirming the copy counts as a
	// verification.
	Refresh(ctx context.Context, src policy.RemoteSource) error
	// Times returns the times of the local copy of url; an error wrapping
	// ErrNotCached means it was never downloaded.
	Times(url string) (Times, error)
	// FileModified returns when a local list file last changed; an error
	// wrapping fs.ErrNotExist means there is no such file.
	FileModified(path string) (time.Time, error)
}

// ErrOutOfBounds means a resolved list broke its bounds and must not be
// applied.
var ErrOutOfBounds = errors.New("list is outside its bounds")

// Resolver resolves lists to address ranges.
type Resolver struct {
	src Source
}

// NewResolver returns a Resolver reading through src.
func NewResolver(src Source) *Resolver {
	return &Resolver{src: src}
}

// Resolved is what a resolution produced.
type Resolved struct {
	// Ranges holds the normalized ranges of each resolved list.
	Ranges map[string][]netip.Prefix
	// Failed holds the guard lists that did not resolve, and why. They fail
	// open one by one (G-4): a guard list guards nothing until it resolves,
	// and nothing else waits for it.
	Failed map[string]error
}

// ErrEmptySource means a source yielded no entries: an empty file or a code
// without entries is a broken source, not an empty list — the list would
// otherwise live on its extras alone, or on nothing.
var ErrEmptySource = errors.New("source has no entries")

// Sizes counts a list's address ranges per family.
type Sizes struct {
	V4, V6 int
}

// Total is the ranges of both families.
func (s Sizes) Total() int { return s.V4 + s.V6 }

func sizesOf(ranges []netip.Prefix) Sizes {
	v4, v6 := netstate.SplitByFamily(ranges)
	return Sizes{V4: len(v4), V6: len(v6)}
}

// Resolve resolves the address ranges of every list the active parts of the
// policy apply. previous holds each list's sizes in the state currently
// applied; a list absent from it is new and checked only against its absolute
// bounds.
//
// An egress list is strict: any failure among them fails the whole
// resolution, since applying some lists fresh and others stale would be a
// policy nobody wrote, and a missing one a leak (I-1). A guard list that fails
// is reported in Failed instead.
func (r *Resolver) Resolve(ctx context.Context, cfg policy.Config, previous map[string]Sizes) (Resolved, error) {
	out := Resolved{Ranges: map[string][]netip.Prefix{}, Failed: map[string]error{}}
	for name, use := range cfg.ListUses() {
		list, _ := cfg.List(name) // Validate guarantees the list exists.
		if !list.HasAddressEntries() {
			continue
		}
		ranges, err := r.ranges(ctx, cfg, list, previous[name])
		switch {
		case err == nil:
			out.Ranges[name] = ranges
		case use.Egress:
			return Resolved{}, err
		default:
			out.Failed[name] = err
		}
	}
	return out, nil
}

func (r *Resolver) ranges(ctx context.Context, cfg policy.Config, list policy.List, previous Sizes) ([]netip.Prefix, error) {
	ranges := slices.Clone(list.ExtraCIDR)
	for _, src := range list.IP {
		got, err := r.src.Addresses(ctx, src, cfg.Geo)
		if err := sourceErr(list, src, len(got), err); err != nil {
			return nil, err
		}
		ranges = append(ranges, got...)
	}
	ranges = netstate.NormalizePrefixes(ranges)
	if err := checkBounds(list, sizesOf(ranges), previous); err != nil {
		return nil, err
	}
	return ranges, nil
}

// sourceErr is why the n entries a source read cannot be taken, or nil.
func sourceErr(list policy.List, src policy.Source, n int, err error) error {
	if err == nil && n == 0 {
		err = ErrEmptySource
	}
	if err != nil {
		return fmt.Errorf("list %q: source %q: %w", list.Name, src.Value, err)
	}
	return nil
}

// ErrNoDomains means a list with domain sources resolved to no domains.
var ErrNoDomains = errors.New("list has no domains")

// Domains returns the domains of every egress list that has domain entries,
// keyed by list name: sources and zones merged, normalized, deduplicated and
// sorted. Every one is checked here, whatever read it: they end up in the
// resolver's config, where anything but a domain would change its meaning.
// Only the egress uses domains, so any failure fails the whole resolution.
func (r *Resolver) Domains(ctx context.Context, cfg policy.Config) (map[string][]string, error) {
	out := map[string][]string{}
	for name, use := range cfg.ListUses() {
		list, _ := cfg.List(name)
		if !use.Egress || !list.HasDomainEntries() {
			continue
		}
		domains := slices.Clone(list.Suffix)
		for _, src := range list.Domain {
			got, err := r.src.Domains(ctx, src, cfg.Geo)
			if err := sourceErr(list, src, len(got), err); err != nil {
				return nil, err
			}
			domains = append(domains, got...)
		}
		for i, d := range domains {
			domains[i] = policy.NormalizeDomain(d)
			if !policy.ValidDomain(domains[i]) {
				return nil, fmt.Errorf("list %q: %q is not a domain", list.Name, d)
			}
		}
		slices.Sort(domains)
		domains = slices.Compact(domains)
		if len(domains) == 0 {
			return nil, fmt.Errorf("%w: %q", ErrNoDomains, list.Name)
		}
		out[list.Name] = domains
	}
	return out, nil
}

// checkBounds checks a list's sizes: the absolute bounds hold for its ranges
// of both families together, the largest change against the applied list for
// each family on its own — a list losing all its IPv4 ranges while keeping
// its IPv6 ones has not changed by half.
func checkBounds(list policy.List, size, previous Sizes) error {
	b := list.Bounds
	if n := size.Total(); n < b.Min || n > b.Max {
		return fmt.Errorf("%w: %q has %d ranges, allowed %d..%d", ErrOutOfBounds, list.Name, n, b.Min, b.Max)
	}
	for _, f := range []struct {
		family         string
		size, previous int
	}{
		{"IPv4", size.V4, previous.V4},
		{"IPv6", size.V6, previous.V6},
	} {
		if f.previous == 0 {
			continue
		}
		change := math.Abs(float64(f.size-f.previous)) / float64(f.previous)
		if change > b.MaxChange {
			return fmt.Errorf("%w: %q changed by %.0f%% (%d → %d %s ranges), allowed %.0f%%",
				ErrOutOfBounds, list.Name, change*100, f.previous, f.size, f.family, b.MaxChange*100)
		}
	}
	return nil
}

// Remote keeps the config's remote sources fresh.
type Remote struct {
	dl  Downloader
	now func() time.Time
	// spread delays every due time of this node by the same fraction of the
	// refresh, so that a fleet installed at once does not download at once.
	spread float64

	mu sync.Mutex
	// retries holds the sources whose last download failed, by URL.
	retries map[string]retry
}

// retry is a failed download: when it failed, and how long the source rests
// before the next attempt.
type retry struct {
	at   time.Time
	wait time.Duration
}

// firstRetry is the rest after a first failure — the cadence at which the
// agent looks for due copies. Each further failure doubles it, up to the
// source's refresh: a source that never verifies (a checksum that never
// matches) must not cost a geo file's download every pass.
const firstRetry = 10 * time.Minute

// MaxSpread is the largest delay spread adds, as a fraction of the refresh.
const MaxSpread = 0.1

// NewRemote returns a Remote downloading through dl. spread, in [0, MaxSpread),
// is this node's share of the delay; tests pass zero.
func NewRemote(dl Downloader, now func() time.Time, spread float64) *Remote {
	return &Remote{dl: dl, now: now, spread: min(max(spread, 0), MaxSpread), retries: map[string]retry{}}
}

// Refresh downloads the copies that are due: missing, or older than their
// refresh. A failed download leaves its copy due, retried after a rest that
// grows with every failure; it does not stop the others, and all failures are
// returned together.
func (r *Remote) Refresh(ctx context.Context, cfg policy.Config) error {
	return r.refresh(ctx, cfg, r.due)
}

// RefreshAll downloads every copy now, due or resting or not.
func (r *Remote) RefreshAll(ctx context.Context, cfg policy.Config) error {
	return r.refresh(ctx, cfg, func(policy.RemoteSource) bool { return true })
}

func (r *Remote) refresh(ctx context.Context, cfg policy.Config, want func(policy.RemoteSource) bool) error {
	var errs []error
	for _, src := range cfg.RemoteSources() {
		if !want(src) {
			continue
		}
		err := r.dl.Refresh(ctx, src)
		if ctx.Err() != nil {
			// Cut short by the caller: no verdict on the source, and no
			// time for the rest.
			errs = append(errs, fmt.Errorf("refresh %s: %w", src.URL, ctx.Err()))
			break
		}
		r.record(src, err)
		if err != nil {
			errs = append(errs, fmt.Errorf("refresh %s: %w", src.URL, err))
		}
	}
	return errors.Join(errs...)
}

// record notes the outcome of a download of src.
func (r *Remote) record(src policy.RemoteSource, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err == nil {
		delete(r.retries, src.URL)
		return
	}
	wait := firstRetry
	if prev, ok := r.retries[src.URL]; ok {
		wait = min(2*prev.wait, max(src.Refresh, firstRetry))
	}
	r.retries[src.URL] = retry{at: r.now(), wait: wait}
}

// due reports whether the copy of src should be downloaded: it is not resting
// after a failure, and it is missing or older than its refresh.
func (r *Remote) due(src policy.RemoteSource) bool {
	r.mu.Lock()
	failed, ok := r.retries[src.URL]
	r.mu.Unlock()
	if ok && r.now().Sub(failed.at) < failed.wait {
		return false
	}
	t, err := r.dl.Times(src.URL)
	if err != nil {
		return true
	}
	limit := src.Refresh + time.Duration(float64(src.Refresh)*r.spread)
	return r.now().Sub(t.Verified) >= limit
}

// Copy is the state of a local copy: of a remote source, or of a local file
// source, which is its own copy.
type Copy struct {
	// Updated is when the copy was last verified current. A local file is
	// never refreshed — it is current by definition — so its Updated is its
	// Modified, and its age is no sign of staleness.
	Updated time.Time
	// Modified is when the content last changed: a new download, or an edit
	// of the local file. A change of it is what makes the lists re-read.
	Modified time.Time
	// Missing means there is no copy: never downloaded, or no such file.
	Missing bool
	// Err is why the state of a copy that may exist could not be read.
	Err error
}

// FileKey is the key of a local file source in Copies.
func FileKey(path string) string { return "file:" + path }

// Copies returns the local copy of every remote source of the config, keyed
// by URL, and of every local file source, keyed by FileKey.
func (r *Remote) Copies(cfg policy.Config) map[string]Copy {
	out := map[string]Copy{}
	for _, u := range cfg.RemoteURLs() {
		t, err := r.dl.Times(u)
		out[u] = copyOf(t, err, ErrNotCached)
	}
	for _, path := range localFiles(cfg) {
		modified, err := r.dl.FileModified(path)
		out[FileKey(path)] = copyOf(Times{Verified: modified, Modified: modified}, err, fs.ErrNotExist)
	}
	return out
}

// copyOf is the Copy of a read of t; an error that is missing means there is
// no copy.
func copyOf(t Times, err, missing error) Copy {
	switch {
	case err == nil:
		return Copy{Updated: t.Verified, Modified: t.Modified}
	case errors.Is(err, missing):
		return Copy{Missing: true}
	default:
		return Copy{Err: err}
	}
}

// localFiles returns the paths of the config's local file sources, each once.
func localFiles(cfg policy.Config) []string {
	var out []string
	for _, l := range cfg.Lists {
		for _, src := range slices.Concat(l.IP, l.Domain) {
			if src.Kind == policy.SourceFile && !slices.Contains(out, src.Value) {
				out = append(out, src.Value)
			}
		}
	}
	return out
}
