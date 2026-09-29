package geodat_test

import (
	"errors"
	"net/netip"
	"slices"
	"testing"

	"github.com/lib4u/vnm/internal/infrastructure/geodat"
)

// A minimal protobuf encoder, to build fixtures in the exact wire format of the
// v2fly files without shipping binary blobs.

func appendVarint(b []byte, v uint64) []byte {
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

func bytesField(num int, v []byte) []byte {
	b := appendVarint(nil, uint64(num)<<3|2)
	b = appendVarint(b, uint64(len(v)))
	return append(b, v...)
}

func varintField(num int, v uint64) []byte {
	return appendVarint(appendVarint(nil, uint64(num)<<3), v)
}

func cidr(p netip.Prefix) []byte {
	return slices.Concat(bytesField(1, p.Addr().AsSlice()), varintField(2, uint64(p.Bits())))
}

func geoIPFile(entries map[string][]netip.Prefix, order []string) []byte {
	var file []byte
	for _, code := range order {
		entry := bytesField(1, []byte(code))
		for _, p := range entries[code] {
			entry = append(entry, bytesField(2, cidr(p))...)
		}
		// An unknown fixed32 field must be skipped, not choke the reader.
		entry = append(entry, appendVarint(nil, 9<<3|5)...)
		entry = append(entry, 0, 0, 0, 0)
		file = append(file, bytesField(1, entry)...)
	}
	return file
}

func geoSiteFile(code string, domains []geodat.Domain) []byte {
	entry := bytesField(1, []byte(code))
	for _, d := range domains {
		entry = append(entry, bytesField(2, slices.Concat(varintField(1, uint64(d.Kind)), bytesField(2, []byte(d.Value))))...)
	}
	return bytesField(1, entry)
}

func TestGeoIP(t *testing.T) {
	ru := []netip.Prefix{netip.MustParsePrefix("5.8.0.0/19"), netip.MustParsePrefix("2a00:1148::/32")}
	file := geoIPFile(map[string][]netip.Prefix{
		// "RUS" first: a prefix-based match would wrongly return it for "ru".
		"RUS": {netip.MustParsePrefix("1.1.1.0/24")},
		"RU":  ru,
	}, []string{"RUS", "RU"})

	got, err := geodat.GeoIP(file, "ru")
	if err != nil {
		t.Fatalf("GeoIP: %v", err)
	}
	if !slices.Equal(got, ru) {
		t.Fatalf("GeoIP = %v, want %v", got, ru)
	}
}

func TestGeoSite(t *testing.T) {
	want := []geodat.Domain{
		{Kind: geodat.DomainSuffix, Value: "vk.com"},
		{Kind: geodat.DomainFull, Value: "www.gosuslugi.ru"},
		{Kind: geodat.DomainKeyword, Value: "yandex"},
	}
	got, err := geodat.GeoSite(geoSiteFile("CATEGORY-RU", want), "category-ru")
	if err != nil {
		t.Fatalf("GeoSite: %v", err)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("GeoSite = %v, want %v", got, want)
	}
}

func TestNotFound(t *testing.T) {
	file := geoIPFile(map[string][]netip.Prefix{"DE": nil}, []string{"DE"})
	if _, err := geodat.GeoIP(file, "ru"); !errors.Is(err, geodat.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

// A truncated download, or an HTML error page served in place of the file,
// must fail loudly — never read as an empty or partial list.
func TestMalformedInput(t *testing.T) {
	good := geoIPFile(map[string][]netip.Prefix{"RU": {netip.MustParsePrefix("5.8.0.0/19")}}, []string{"RU"})
	for name, data := range map[string][]byte{
		"truncated": good[:len(good)-3],
		"html":      []byte("<html><body>502 Bad Gateway</body></html>"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := geodat.GeoIP(data, "ru"); err == nil {
				t.Fatal("malformed input accepted")
			}
		})
	}
}
