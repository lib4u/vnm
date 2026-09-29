package listcache

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
)

const (
	// checksumSuffix names the checksum file published next to a source.
	checksumSuffix = ".sha256sum"
	// maxRedirects is the hops a download may take, as net/http allows by
	// default.
	maxRedirects = 10
)

// request is one GET of a remote file.
type request struct {
	url   string
	limit int64
	// sameHost refuses a redirect to another host.
	sameHost bool
	// etag, when set, makes the request conditional on it.
	etag string
}

// response is what a GET returned beside its body.
type response struct {
	// notModified means a conditional request found the file unchanged.
	notModified bool
	etag        string
	// whole means the transfer proved it arrived complete: the body matched
	// its Content-Length, or it came gzip-compressed, whose trailer checks
	// length and CRC.
	whole bool
}

// get streams the body of a successful GET to w, refusing bodies over the
// request's limit. A conditional request answered 304 writes nothing.
func (c *Cache) get(ctx context.Context, r request, w io.Writer) (response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.url, nil)
	if err != nil {
		return response{}, fmt.Errorf("request %s: %w", r.url, err)
	}
	client := c.anyHost
	if r.sameHost {
		client = c.sameHost
	}
	if r.etag != "" {
		req.Header.Set("If-None-Match", r.etag)
	}
	resp, err := client.Do(req)
	if err != nil {
		return response{}, fmt.Errorf("get %s: %w", r.url, err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotModified && r.etag != "":
		return response{notModified: true}, nil
	case resp.StatusCode != http.StatusOK:
		return response{}, fmt.Errorf("get %s: status %s", r.url, resp.Status)
	}
	n, err := io.Copy(w, io.LimitReader(resp.Body, r.limit+1))
	if err != nil {
		return response{}, fmt.Errorf("read %s: %w", r.url, err)
	}
	if n > r.limit {
		return response{}, fmt.Errorf("get %s: larger than %d bytes", r.url, r.limit)
	}
	if resp.ContentLength >= 0 && n != resp.ContentLength {
		return response{}, fmt.Errorf("get %s: %d bytes of %d", r.url, n, resp.ContentLength)
	}
	return response{etag: resp.Header.Get("ETag"), whole: resp.ContentLength >= 0 || resp.Uncompressed}, nil
}

// withRedirects returns a copy of client that keeps every redirect on https —
// a hop in the clear could be rewritten by anyone on the path — and, with
// sameHost, on the host first asked. A file verified by its checksum may move
// to another host: the geo releases on github.com redirect to their CDN.
func withRedirects(client *http.Client, sameHost bool) *http.Client {
	var out http.Client
	if client != nil {
		out = *client
	}
	next := out.CheckRedirect
	out.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		switch {
		case req.URL.Scheme != "https":
			return fmt.Errorf("redirected to %s, not https", req.URL.Redacted())
		case sameHost && hostOf(req.URL) != hostOf(via[0].URL):
			return fmt.Errorf("redirected to another host, %s", req.URL.Host)
		case next != nil:
			return next(req, via)
		case len(via) >= maxRedirects:
			return fmt.Errorf("stopped after %d redirects", maxRedirects)
		}
		return nil
	}
	return &out
}

// hostOf is the host and port u names, in one spelling.
func hostOf(u *url.URL) string {
	port := u.Port()
	if port == "" {
		port = "443" // redirects are https only
	}
	return net.JoinHostPort(strings.ToLower(u.Hostname()), port)
}

// checksum fetches the published sha256 of url, in sha256sum format.
func (c *Cache) checksum(ctx context.Context, url string) (string, error) {
	var buf bytes.Buffer
	if _, err := c.get(ctx, request{url: url + checksumSuffix, limit: 1 << 10}, &buf); err != nil {
		return "", err
	}
	sum, _, _ := strings.Cut(strings.TrimSpace(buf.String()), " ")
	if len(sum) != sha256.Size*2 {
		return "", fmt.Errorf("%w: %s%s does not hold a sha256", ErrChecksum, url, checksumSuffix)
	}
	if _, err := hex.DecodeString(sum); err != nil {
		return "", fmt.Errorf("%w: %s%s: %w", ErrChecksum, url, checksumSuffix, err)
	}
	return strings.ToLower(sum), nil
}
