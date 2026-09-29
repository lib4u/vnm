package atomicfile_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lib4u/vnm/internal/infrastructure/atomicfile"
)

func TestWriteFileReplaces(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "state.json")
	for _, content := range []string{"first", "second"} {
		if err := atomicfile.WriteFile(path, []byte(content), 0o640); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		got, err := os.ReadFile(path)
		if err != nil || string(got) != content {
			t.Fatalf("content = %q, %v; want %q", got, err, content)
		}
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("mode = %v, %v", info.Mode(), err)
	}
	requireOnly(t, filepath.Dir(path), "state.json")
}

// An aborted replacement leaves the old content and no temporary file.
func TestAbortKeepsOldContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "list.txt")
	if err := atomicfile.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := atomicfile.Create(path, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("half a downl")); err != nil {
		t.Fatal(err)
	}
	f.Abort()
	f.Abort() // idempotent, so it can be deferred

	got, err := os.ReadFile(path)
	if err != nil || string(got) != "old" {
		t.Fatalf("content = %q, %v", got, err)
	}
	requireOnly(t, filepath.Dir(path), "list.txt")
}

func requireOnly(t *testing.T, dir, name string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != name {
		t.Fatalf("directory holds %v, want only %s", entries, name)
	}
}
