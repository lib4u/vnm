package policy

import (
	"slices"
	"time"
)

// Refresh cadence of remote sources (guard ТЗ §3.1).
const (
	// DefaultRefresh is how old a local copy may get when its list sets no
	// refresh of its own.
	DefaultRefresh = 24 * time.Hour
	// MinRefresh keeps a node from hammering a source.
	MinRefresh = time.Hour
)

// Checksum is how a downloaded copy is verified before it replaces the
// previous one.
type Checksum uint8

const (
	// ChecksumSHA256Sum, the zero value and so the default, requires the
	// "<file>.sha256sum" published beside the file.
	ChecksumSHA256Sum Checksum = iota
	// ChecksumNone is for sources that publish no checksum: the copy must then
	// parse as a whole before it is kept, and the list must set its bounds.
	ChecksumNone
)

// Format is what a remote file holds.
type Format uint8

const (
	FormatUnknown Format = iota
	// FormatGeoIP and FormatGeoSite are the v2fly geo files.
	FormatGeoIP
	FormatGeoSite
	// FormatRanges is one address or range per line.
	FormatRanges
	// FormatDomains is one domain per line.
	FormatDomains
)

// RemoteSource is a file the node downloads, as every list reading it asks.
type RemoteSource struct {
	URL      string
	Format   Format
	Checksum Checksum
	// Refresh is how old the local copy may get: the shortest of the lists
	// reading it.
	Refresh time.Duration
}

// RefreshOrDefault is the list's refresh, or the default when it sets none.
func (l List) RefreshOrDefault() time.Duration {
	if l.Refresh == 0 {
		return DefaultRefresh
	}
	return l.Refresh
}

// RemoteSources returns every file the lists read from the network, each
// once, in the order the lists name them.
func (c Config) RemoteSources() []RemoteSource {
	var out []RemoteSource
	for _, list := range c.Lists {
		for _, src := range list.remoteSources(c.Geo) {
			i := slices.IndexFunc(out, func(r RemoteSource) bool { return r.URL == src.URL })
			if i < 0 {
				out = append(out, src)
				continue
			}
			out[i].Refresh = min(out[i].Refresh, src.Refresh)
		}
	}
	return out
}

// RemoteURLs returns the URLs the policy reads its lists from, each once.
func (c Config) RemoteURLs() []string {
	var urls []string
	for _, r := range c.RemoteSources() {
		urls = append(urls, r.URL)
	}
	return urls
}

// ListRemoteURLs returns the URLs one list reads.
func (c Config) ListRemoteURLs(l List) []string {
	var urls []string
	for _, r := range l.remoteSources(c.Geo) {
		urls = append(urls, r.URL)
	}
	return urls
}

func (l List) remoteSources(geo GeoFiles) []RemoteSource {
	var out []RemoteSource
	add := func(url string, f Format, sum Checksum) {
		if url != "" && !slices.ContainsFunc(out, func(r RemoteSource) bool { return r.URL == url }) {
			out = append(out, RemoteSource{URL: url, Format: f, Checksum: sum, Refresh: l.RefreshOrDefault()})
		}
	}
	for _, src := range l.IP {
		switch src.Kind {
		case SourceGeoIP:
			add(geo.GeoIP, FormatGeoIP, ChecksumSHA256Sum)
		case SourceURL:
			add(src.Value, FormatRanges, l.Checksum)
		}
	}
	for _, src := range l.Domain {
		switch src.Kind {
		case SourceGeoSite:
			add(geo.GeoSite, FormatGeoSite, ChecksumSHA256Sum)
		case SourceURL:
			add(src.Value, FormatDomains, l.Checksum)
		}
	}
	return out
}

// validateRemote checks the lists' download settings, and that no file is
// read two ways: one copy cannot be verified or parsed differently per list.
func (c Config) validateRemote(p *problems) {
	seen := map[string]RemoteSource{}
	for _, l := range c.Lists {
		sources := l.remoteSources(c.Geo)
		if l.Refresh != 0 {
			switch {
			case len(sources) == 0:
				p.add("list %q: refresh is set, but the list reads nothing remote", l.Name)
			case l.Refresh < MinRefresh:
				p.add("list %q: refresh %v is below %v", l.Name, l.Refresh, MinRefresh)
			}
		}
		if l.Checksum == ChecksumNone {
			for _, s := range slices.Concat(l.IP, l.Domain) {
				if s.Kind == SourceGeoIP || s.Kind == SourceGeoSite {
					p.add("list %q: checksum none applies to url: sources; the geo files are always verified", l.Name)
				}
			}
		}
		for _, s := range sources {
			prev, ok := seen[s.URL]
			if ok && (prev.Format != s.Format || prev.Checksum != s.Checksum) {
				p.add("list %q: %s is read by another list with other entries or another checksum setting", l.Name, s.URL)
			}
			seen[s.URL] = s
		}
	}
}
