// Package filelock serialises state changes between the agent and the CLI
// (ТЗ §7.3): both change nft, rules and routes, and two interleaved applies
// would leave a mix of two states in the kernel.
package filelock

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// ErrBusy means the lock was not acquired before the context ended.
var ErrBusy = errors.New("another vnm process is changing the node")

// pollInterval is how often a waiting process retries the lock.
const pollInterval = 100 * time.Millisecond

// Lock is a held lock.
type Lock struct {
	f *os.File
}

// Acquire takes an exclusive lock on path, waiting until ctx ends. The kernel
// releases the lock when the process dies, so a crashed holder never blocks
// the node.
func Acquire(ctx context.Context, path string) (*Lock, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create lock directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock %s: %w", path, err)
	}

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return &Lock{f: f}, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			f.Close()
			return nil, fmt.Errorf("lock %s: %w", path, err)
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, fmt.Errorf("%w: %w", ErrBusy, ctx.Err())
		case <-ticker.C:
		}
	}
}

// Release frees the lock.
func (l *Lock) Release() error {
	// Closing the descriptor drops the flock with it.
	return l.f.Close()
}

// Locker takes the state lock at a fixed path, waiting at most Wait.
type Locker struct {
	Path string
	Wait time.Duration
}

// Lock takes the lock and returns its release.
func (l Locker) Lock(ctx context.Context) (func() error, error) {
	ctx, cancel := context.WithTimeout(ctx, l.Wait)
	defer cancel()
	lock, err := Acquire(ctx, l.Path)
	if err != nil {
		return nil, err
	}
	return lock.Release, nil
}
