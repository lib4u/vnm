package filesum_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lib4u/vnm/internal/infrastructure/filesum"
)

func TestSHA256(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(path, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := filesum.SHA256(path)
	if want := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"; err != nil || got != want {
		t.Fatalf("SHA256 = %s, %v", got, err)
	}
	if _, err := filesum.SHA256(filepath.Join(t.TempDir(), "absent")); !os.IsNotExist(err) {
		t.Fatalf("absent file: %v", err)
	}
}
