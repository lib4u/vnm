package listcache

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/lib4u/vnm/internal/domain/policy"
	"github.com/lib4u/vnm/internal/infrastructure/geodat"
)

// Addresses reads the ranges of a source from local data.
func (c *Cache) Addresses(_ context.Context, src policy.Source, geo policy.GeoFiles) ([]netip.Prefix, error) {
	switch src.Kind {
	case policy.SourceGeoIP:
		data, err := c.read(geo.GeoIP)
		if err != nil {
			return nil, err
		}
		return geodat.GeoIP(data, src.Value)
	case policy.SourceURL, policy.SourceFile:
		data, err := c.text(src)
		if err != nil {
			return nil, err
		}
		return parseRanges(data)
	default:
		return nil, fmt.Errorf("source %q does not yield addresses", src.Value)
	}
}

// Domains reads the domains of a source from local data, each matching itself
// and its subdomains. Of a geosite category only suffix and full entries are
// taken: keyword and regex entries have no form a resolver can match, and the
// category the fleet uses has none. A full entry widens to its subdomains too
// — the resolver's sets know no other match — which errs on the side of
// sending more through the list, never less.
func (c *Cache) Domains(_ context.Context, src policy.Source, geo policy.GeoFiles) ([]string, error) {
	switch src.Kind {
	case policy.SourceGeoSite:
		data, err := c.read(geo.GeoSite)
		if err != nil {
			return nil, err
		}
		entries, err := geodat.GeoSite(data, src.Value)
		if err != nil {
			return nil, err
		}
		var out []string
		for _, e := range entries {
			if e.Kind != geodat.DomainSuffix && e.Kind != geodat.DomainFull {
				continue
			}
			d, err := domain(e.Value)
			if err != nil {
				return nil, fmt.Errorf("geosite %q: %w", src.Value, err)
			}
			out = append(out, d)
		}
		return out, nil
	case policy.SourceURL, policy.SourceFile:
		data, err := c.text(src)
		if err != nil {
			return nil, err
		}
		return parseDomains(data)
	default:
		return nil, fmt.Errorf("source %q does not yield domains", src.Value)
	}
}

// text reads a list of one entry per line: the local copy of a url: source,
// or a file: source itself.
func (c *Cache) text(src policy.Source) ([]byte, error) {
	if src.Kind == policy.SourceURL {
		return c.read(src.Value)
	}
	data, err := os.ReadFile(src.Value)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", src.Value, err)
	}
	return data, nil
}

// errNotTerminated means a download's last line has no newline and nothing
// else proves the transfer complete: it may have been cut off inside that
// line, "…/24" arriving as a valid "…/2".
var errNotTerminated = errors.New("the last line is not terminated and the transfer is not known complete")

// parses checks that a downloaded list parses as a whole and holds at least
// one entry: an empty file is a broken publication, not an empty list. whole
// says the transfer proved itself complete; real lists often lack the final
// newline (antiscanner.list, skipa.list), which is only required otherwise.
func parses(data []byte, f policy.Format, whole bool) error {
	if !whole && !bytes.HasSuffix(data, []byte("\n")) {
		return errNotTerminated
	}
	var n int
	var err error
	switch f {
	case policy.FormatRanges:
		var got []netip.Prefix
		got, err = parseRanges(data)
		n = len(got)
	case policy.FormatDomains:
		var got []string
		got, err = parseDomains(data)
		n = len(got)
	default:
		return fmt.Errorf("format %d cannot be verified by parsing", f)
	}
	if err != nil {
		return err
	}
	if n == 0 {
		return errors.New("no entries")
	}
	return nil
}

// parseRanges reads one address or range per line; blank lines and "#"
// comments are skipped. Any other line is an error: a list that half-parsed
// would silently cover half of what it should.
func parseRanges(data []byte) ([]netip.Prefix, error) {
	var out []netip.Prefix
	err := eachLine(data, func(n int, line string) error {
		p, err := parseRange(line)
		if err != nil {
			return fmt.Errorf("line %d: %w", n, err)
		}
		out = append(out, p)
		return nil
	})
	return out, err
}

// parseRange reads an address or a range. A range with host bits set means
// the range it masks to, as nft reads it: real lists carry such entries
// ("195.182.151.212/29" in government_networks). A line cut in the middle of
// its prefix length is caught by the list having to end with a newline, not
// here. An address with a zone names a link, not a destination: an error.
// IPv4-mapped entries are turned into IPv4 by netstate.NormalizePrefixes.
func parseRange(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		addr, err := netip.ParseAddr(s)
		switch {
		case err != nil:
			return netip.Prefix{}, fmt.Errorf("%q is neither an address nor a range", s)
		case addr.Zone() != "":
			return netip.Prefix{}, fmt.Errorf("%q has a zone, it is no destination", s)
		}
		p = netip.PrefixFrom(addr, addr.BitLen())
	}
	return p.Masked(), nil
}

// parseDomains reads one domain per line; blank lines and "#" comments are
// skipped, anything else that is not a domain is an error.
func parseDomains(data []byte) ([]string, error) {
	var out []string
	err := eachLine(data, func(n int, line string) error {
		d, err := domain(line)
		if err != nil {
			return fmt.Errorf("line %d: %w", n, err)
		}
		out = append(out, d)
		return nil
	})
	return out, err
}

// domain returns s as a list holds it, or an error when it is no domain:
// domains end up in the resolver's config, where a newline or an empty name
// would change its meaning.
func domain(s string) (string, error) {
	d := policy.NormalizeDomain(s)
	if !policy.ValidDomain(d) {
		return "", fmt.Errorf("%q is not a domain", s)
	}
	return d, nil
}

// eachLine calls fn with every non-blank line, comments stripped.
func eachLine(data []byte, fn func(n int, line string) error) error {
	sc := bufio.NewScanner(bytes.NewReader(data))
	for n := 1; sc.Scan(); n++ {
		line, _, _ := strings.Cut(sc.Text(), "#")
		if line = strings.TrimSpace(line); line == "" {
			continue
		}
		if err := fn(n, line); err != nil {
			return err
		}
	}
	return sc.Err()
}
