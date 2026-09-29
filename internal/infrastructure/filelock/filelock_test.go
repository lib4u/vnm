package filelock_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/lib4u/vnm/internal/infrastructure/filelock"
)

func TestSecondHolderWaitsThenGetsTheLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run", "state.lock")
	first, err := filelock.Acquire(context.Background(), path)
	if err != nil {
		t.Fatalf("first Acquire: %v", err)
	}

	// While the first holds it, the second times out.
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if _, err := filelock.Acquire(ctx, path); !errors.Is(err, filelock.ErrBusy) {
		t.Fatalf("second Acquire while held: want ErrBusy, got %v", err)
	}

	// Once released, the second gets it.
	if err := first.Release(); err != nil {
		t.Fatal(err)
	}
	second, err := filelock.Acquire(context.Background(), path)
	if err != nil {
		t.Fatalf("second Acquire after release: %v", err)
	}
	if err := second.Release(); err != nil {
		t.Fatal(err)
	}
}
