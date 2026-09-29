// Package statefile keeps the last good state on disk (ТЗ §7.1). It is what the
// boot unit applies before the network comes up, so it must survive a crash in
// the middle of a write: a torn file there would leave the node with no policy
// at all during boot.
package statefile

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/lib4u/vnm/internal/domain/netstate"
	"github.com/lib4u/vnm/internal/infrastructure/atomicfile"
	"github.com/lib4u/vnm/internal/usecase/apply"
)

// fileName is the last good state inside the state directory.
const fileName = "last-good.json"

// Store is a state file in a directory.
type Store struct {
	dir string
}

var _ apply.Store = (*Store)(nil)

// New returns a Store in dir. The directory is created on the first save.
func New(dir string) *Store {
	return &Store{dir: dir}
}

// LastGood reads the stored state. A missing file means no state yet; an
// unreadable or corrupt one is an error — silently treating it as "no state"
// would boot the node without a policy.
func (s *Store) LastGood() (netstate.State, bool, error) {
	data, err := os.ReadFile(s.path())
	if errors.Is(err, fs.ErrNotExist) {
		return netstate.State{}, false, nil
	}
	if err != nil {
		return netstate.State{}, false, fmt.Errorf("read %s: %w", s.path(), err)
	}
	var state netstate.State
	if err := json.Unmarshal(data, &state); err != nil {
		return netstate.State{}, false, fmt.Errorf("decode %s: %w", s.path(), err)
	}
	return state, true, nil
}

// SaveLastGood replaces the stored state atomically.
func (s *Store) SaveLastGood(state netstate.State) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode state: %w", err)
	}
	return atomicfile.WriteFile(s.path(), data, 0o600)
}

func (s *Store) path() string {
	return filepath.Join(s.dir, fileName)
}
