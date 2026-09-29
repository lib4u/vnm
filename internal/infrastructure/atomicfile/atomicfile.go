// Package atomicfile replaces files so that a reader — or a crash — only ever
// sees the old content or the new one, never a mix: the new content goes to a
// temporary file in the same directory, is synced, renamed over the target, and
// the directory is synced so the rename itself survives a power loss.
package atomicfile

import (
	"fmt"
	"os"
	"path/filepath"
)

// File is a pending replacement. Write to it, then Commit or Abort.
type File struct {
	*os.File
	path string
	done bool
}

// Create starts a replacement of path with the given mode. Missing parent
// directories are created traversable: a file meant to be world-readable, such
// as a config another daemon reads after dropping privileges, must stay so.
func Create(path string, mode os.FileMode) (*File, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return nil, fmt.Errorf("create temporary file for %s: %w", path, err)
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return nil, fmt.Errorf("chmod temporary file for %s: %w", path, err)
	}
	return &File{File: tmp, path: path}, nil
}

// Commit makes the written content the file's content.
func (f *File) Commit() error {
	if f.done {
		return fmt.Errorf("%s: replacement already finished", f.path)
	}
	f.done = true
	name := f.Name()
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(name)
		return fmt.Errorf("sync %s: %w", name, err)
	}
	if err := f.Close(); err != nil {
		os.Remove(name)
		return fmt.Errorf("close %s: %w", name, err)
	}
	if err := os.Rename(name, f.path); err != nil {
		os.Remove(name)
		return fmt.Errorf("replace %s: %w", f.path, err)
	}
	return syncDir(filepath.Dir(f.path))
}

// Abort drops the replacement; the file keeps its old content. It is a no-op
// after Commit, so it can be deferred.
func (f *File) Abort() {
	if f.done {
		return
	}
	f.done = true
	f.Close()
	os.Remove(f.Name())
}

// WriteFile replaces path with data.
func WriteFile(path string, data []byte, mode os.FileMode) error {
	f, err := Create(path, mode)
	if err != nil {
		return err
	}
	defer f.Abort()
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return f.Commit()
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open %s: %w", dir, err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("sync %s: %w", dir, err)
	}
	return nil
}
