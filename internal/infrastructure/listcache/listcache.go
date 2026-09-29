// Package listcache keeps local copies of the remote list sources and reads
// list entries from them (ТЗ §7.4).
//
// A copy is replaced only by a download that is verified: by default against
// its published sha256 (the "<file>.sha256sum" next to it, in sha256sum
// format — the convention of the Loyalsoldier geo releases); for sources that
// publish none, by parsing the whole file (guard ТЗ §3.2). Either way a
// truncated transfer or an error page never becomes a list. Reading never
// touches the network.
//
// Beside each copy lie two small files: one whose mtime records the last
// verification, so that confirming a copy does not touch the copy's own mtime
// (the time its content changed), and the ETag of the copy of a source
// without a checksum, for conditional requests.
package listcache

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/lib4u/vnm/internal/domain/policy"
	"github.com/lib4u/vnm/internal/infrastructure/atomicfile"
	"github.com/lib4u/vnm/internal/infrastructure/filesum"
	"github.com/lib4u/vnm/internal/usecase/lists"
)

const (
	// maxFileSize caps a download; the geo files are tens of megabytes.
	maxFileSize = 128 << 20
	// maxListSize caps a download verified by parsing: a plain list of
	// ranges or domains, not a geo file.
	maxListSize = 16 << 20
	// etagSuffix names the file keeping the ETag of an unverified source's
	// copy, for conditional requests.
	etagSuffix = ".etag"
	// verifiedSuffix names the file whose mtime is the copy's last
	// verification.
	verifiedSuffix = ".verified"
	// staleTemp is how old an unfinished download must be to have been left
	// behind by a crash: a live one ends within the download timeout.
	staleTemp = time.Hour
)

// ErrUnparsable means a download verified by parsing did not parse.
var ErrUnparsable = errors.New("download is not a valid list")

// ErrChecksum means a download does not match its published checksum.
var ErrChecksum = errors.New("checksum mismatch")

// ErrNotCached means a remote source has not been downloaded yet.
var ErrNotCached = lists.ErrNotCached

// Cache is a directory of local copies.
type Cache struct {
	dir string
	// anyHost fetches files verified by their checksum, which may move to
	// another host; sameHost, files verified by parsing, which may not.
	anyHost, sameHost *http.Client
}

var (
	_ lists.Source     = (*Cache)(nil)
	_ lists.Downloader = (*Cache)(nil)
)

// New returns a Cache in dir that downloads with client.
func New(dir string, client *http.Client) *Cache {
	return &Cache{dir: dir, anyHost: withRedirects(client, false), sameHost: withRedirects(client, true)}
}

// Refresh downloads a source and replaces the local copy if the content is
// verified and differs; verified and unchanged, the copy is confirmed. Any
// failure leaves the previous copy untouched. It first clears what earlier
// downloads a crash cut short left behind.
func (c *Cache) Refresh(ctx context.Context, src policy.RemoteSource) error {
	cleanErr := c.removeStaleTemps()
	var err error
	if src.Checksum == policy.ChecksumNone {
		err = c.refreshParsed(ctx, src)
	} else {
		err = c.refreshChecksummed(ctx, src.URL)
	}
	return errors.Join(err, cleanErr)
}

// refreshChecksummed replaces the copy with a download matching the sha256
// published beside it.
func (c *Cache) refreshChecksummed(ctx context.Context, url string) error {
	want, err := c.checksum(ctx, url)
	if err != nil {
		return err
	}
	if current, err := filesum.SHA256(c.path(url)); err == nil && current == want {
		return c.confirm(url)
	}
	f, err := atomicfile.Create(c.path(url), 0o600)
	if err != nil {
		return err
	}
	defer f.Abort() // no-op after Commit

	h := sha256.New()
	if _, err := c.get(ctx, request{url: url, limit: maxFileSize}, io.MultiWriter(f, h)); err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return fmt.Errorf("%w: %s is %s, published %s", ErrChecksum, url, got, want)
	}
	return f.Commit()
}

// refreshParsed replaces the copy of a source that publishes no checksum with
// a download that parses as a whole. The request is conditional on the copy's
// ETag: an unchanged file is confirmed without being sent again. Nothing but
// the named host vouches for the file, so no redirect may leave it.
func (c *Cache) refreshParsed(ctx context.Context, src policy.RemoteSource) error {
	file := c.path(src.URL)
	var body bytes.Buffer
	resp, err := c.get(ctx, request{url: src.URL, limit: maxListSize, sameHost: true, etag: c.etag(file)}, &body)
	if err != nil {
		return err
	}
	if resp.notModified {
		return c.confirm(src.URL)
	}
	data := body.Bytes()
	if err := parses(data, src.Format, resp.whole); err != nil {
		return fmt.Errorf("%w: %s: %w", ErrUnparsable, src.URL, err)
	}
	// A server without ETags sends an unchanged file whole: it is confirmed
	// all the same, not rewritten as if it had changed.
	current, _ := os.ReadFile(file) // a copy that cannot be read is replaced
	if bytes.Equal(current, data) {
		err = c.confirm(src.URL)
	} else {
		err = atomicfile.WriteFile(file, data, 0o600)
	}
	if err != nil {
		return err
	}
	return c.saveETag(file, data, resp.etag)
}

// confirm records that the copy of url was verified current, leaving the
// copy itself untouched.
func (c *Cache) confirm(url string) error {
	if err := atomicfile.WriteFile(c.path(url)+verifiedSuffix, nil, 0o600); err != nil {
		return fmt.Errorf("record verification of %s: %w", url, err)
	}
	return nil
}

// etag returns the ETag stored for the copy in file — only if it was stored
// with this very content. A copy and its ETag are written one after the
// other, and two refreshes at once (the agent's and `vnm lists update`) can
// pair one's copy with the other's ETag: a 304 would then confirm, for good, a
// copy the server never sent for it.
func (c *Cache) etag(file string) string {
	stored, err := os.ReadFile(file + etagSuffix)
	if err != nil {
		return ""
	}
	sum, etag, ok := strings.Cut(strings.TrimSpace(string(stored)), " ")
	if !ok {
		return ""
	}
	if current, err := filesum.SHA256(file); err != nil || current != sum {
		return ""
	}
	return etag
}

// saveETag stores the ETag of the copy in file, with the sha256 of the data it
// describes. The ETag only saves a download; a copy without one is still
// valid.
func (c *Cache) saveETag(file string, data []byte, etag string) error {
	if etag == "" {
		return c.remove(file + etagSuffix)
	}
	sum := sha256.Sum256(data)
	return atomicfile.WriteFile(file+etagSuffix, []byte(hex.EncodeToString(sum[:])+" "+etag+"\n"), 0o600)
}

// removeStaleTemps removes the temporary files of downloads a crash cut
// short: atomicfile names them ".<name>.<random>" beside the copy, and no
// other file of the directory starts with a dot.
func (c *Cache) removeStaleTemps() error {
	entries, err := os.ReadDir(c.dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("list %s: %w", c.dir, err)
	}
	var errs []error
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), ".") || !e.Type().IsRegular() {
			continue
		}
		info, err := e.Info()
		if err != nil || time.Since(info.ModTime()) < staleTemp {
			continue // gone meanwhile, or still being written
		}
		errs = append(errs, c.remove(filepath.Join(c.dir, e.Name())))
	}
	return errors.Join(errs...)
}

func (c *Cache) remove(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// Times returns when the local copy of url was last verified current and
// last changed. A verification older than the copy was of a previous copy:
// the download that replaced it verified it anew.
func (c *Cache) Times(url string) (lists.Times, error) {
	file := c.path(url)
	info, err := os.Stat(file)
	if errors.Is(err, fs.ErrNotExist) {
		return lists.Times{}, fmt.Errorf("%w: %s", ErrNotCached, url)
	}
	if err != nil {
		return lists.Times{}, fmt.Errorf("stat local copy of %s: %w", url, err)
	}
	t := lists.Times{Verified: info.ModTime(), Modified: info.ModTime()}
	if v, err := os.Stat(file + verifiedSuffix); err == nil && v.ModTime().After(t.Verified) {
		t.Verified = v.ModTime()
	}
	return t, nil
}

// FileModified returns when a local list file last changed.
func (c *Cache) FileModified(path string) (time.Time, error) {
	info, err := os.Stat(path)
	if err != nil {
		return time.Time{}, fmt.Errorf("stat %s: %w", path, err)
	}
	return info.ModTime(), nil
}

// read returns the local copy of url.
func (c *Cache) read(url string) ([]byte, error) {
	data, err := os.ReadFile(c.path(url))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s", ErrNotCached, url)
	}
	if err != nil {
		return nil, fmt.Errorf("read local copy of %s: %w", url, err)
	}
	return data, nil
}

// path names the local copy of url: a hash keeps different URLs apart, the
// base name keeps the directory readable.
func (c *Cache) path(url string) string {
	sum := sha256.Sum256([]byte(url))
	return filepath.Join(c.dir, hex.EncodeToString(sum[:8])+"-"+path.Base(url))
}
