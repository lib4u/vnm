// Package geodat reads the v2fly geo files (geoip.dat, geosite.dat) the fleet
// already hosts for its clients, so the agent's lists and the clients' routing
// come from one dataset.
//
// The files are protobuf (v2fly router.GeoIPList / router.GeoSiteList). They
// are decoded here directly: three message types do not justify a protobuf
// dependency, and matching category names with strings.Contains on the raw
// bytes gives wrong answers for short codes glued to neighbouring data.
package geodat

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// ErrNotFound means the file has no entry with the requested code.
var ErrNotFound = errors.New("code not found in geo data")

// errStop ends an iteration early once the requested entry is decoded.
var errStop = errors.New("stop")

// Field numbers of the v2fly messages.
const (
	listEntry = 1 // GeoIPList.entry, GeoSiteList.entry

	entryCode   = 1 // GeoIP.country_code, GeoSite.country_code
	geoIPCIDR   = 2 // GeoIP.cidr
	geoSiteItem = 2 // GeoSite.domain

	cidrIP     = 1 // CIDR.ip
	cidrPrefix = 2 // CIDR.prefix

	domainType  = 1 // Domain.type
	domainValue = 2 // Domain.value
)

// GeoIP returns the ranges of the entry with the given code ("ru"), matched
// case-insensitively.
func GeoIP(data []byte, code string) ([]netip.Prefix, error) {
	entry, err := findEntry(data, code)
	if err != nil {
		return nil, err
	}
	var out []netip.Prefix
	err = fields(entry, func(f field) error {
		if f.num != geoIPCIDR {
			return nil
		}
		p, err := decodeCIDR(f.bytes)
		if err != nil {
			return err
		}
		out = append(out, p)
		return nil
	})
	return out, err
}

func decodeCIDR(data []byte) (netip.Prefix, error) {
	var ip []byte
	var bits uint64
	err := fields(data, func(f field) error {
		switch f.num {
		case cidrIP:
			ip = f.bytes
		case cidrPrefix:
			bits = f.varint
		}
		return nil
	})
	if err != nil {
		return netip.Prefix{}, err
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Prefix{}, fmt.Errorf("%w: address of %d bytes", ErrMalformed, len(ip))
	}
	if bits > uint64(addr.BitLen()) {
		return netip.Prefix{}, fmt.Errorf("%w: prefix /%d on %v", ErrMalformed, bits, addr)
	}
	return netip.PrefixFrom(addr, int(bits)), nil
}

// DomainKind is how a geosite entry matches.
type DomainKind uint8

const (
	// DomainKeyword matches any domain containing the value.
	DomainKeyword DomainKind = iota
	// DomainRegex matches a regular expression.
	DomainRegex
	// DomainSuffix matches the domain and all its subdomains.
	DomainSuffix
	// DomainFull matches exactly the domain.
	DomainFull
)

// Domain is one geosite entry.
type Domain struct {
	Kind  DomainKind
	Value string
}

// GeoSite returns the domains of the category with the given code
// ("category-ru"), matched case-insensitively.
func GeoSite(data []byte, code string) ([]Domain, error) {
	entry, err := findEntry(data, code)
	if err != nil {
		return nil, err
	}
	var out []Domain
	err = fields(entry, func(f field) error {
		if f.num != geoSiteItem {
			return nil
		}
		var d Domain
		err := fields(f.bytes, func(df field) error {
			switch df.num {
			case domainType:
				d.Kind = DomainKind(df.varint)
			case domainValue:
				d.Value = string(df.bytes)
			}
			return nil
		})
		if err != nil {
			return err
		}
		out = append(out, d)
		return nil
	})
	return out, err
}

// findEntry returns the raw message of the list entry with the given code.
func findEntry(data []byte, code string) ([]byte, error) {
	var found []byte
	err := fields(data, func(f field) error {
		if f.num != listEntry {
			return nil
		}
		entryCodeValue, err := codeOf(f.bytes)
		if err != nil {
			return err
		}
		if strings.EqualFold(entryCodeValue, code) {
			found = f.bytes
			return errStop
		}
		return nil
	})
	if err != nil && !errors.Is(err, errStop) {
		return nil, err
	}
	if found == nil {
		return nil, fmt.Errorf("%w: %q", ErrNotFound, code)
	}
	return found, nil
}

func codeOf(entry []byte) (string, error) {
	var code string
	err := fields(entry, func(f field) error {
		if f.num == entryCode {
			code = string(f.bytes)
			return errStop
		}
		return nil
	})
	if err != nil && !errors.Is(err, errStop) {
		return "", err
	}
	return code, nil
}
