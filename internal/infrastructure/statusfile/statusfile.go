// Package statusfile keeps the agent's last snapshot on disk as JSON, for
// `vnm status` and `vnm doctor`: the CLI reports what the agent sees without
// talking to it.
package statusfile

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/lib4u/vnm/internal/domain/policy"
	"github.com/lib4u/vnm/internal/infrastructure/atomicfile"
	"github.com/lib4u/vnm/internal/usecase/agent"
	"github.com/lib4u/vnm/internal/usecase/exits"
)

// File is the snapshot file.
type File struct {
	path string
}

var _ agent.Metrics = (*File)(nil)

// New returns the snapshot file at path.
func New(path string) *File {
	return &File{path: path}
}

// Publish writes the snapshot, replacing the file atomically.
func (f *File) Publish(s agent.Snapshot) error {
	data, err := json.MarshalIndent(toDTO(s), "", "  ")
	if err != nil {
		return fmt.Errorf("encode status: %w", err)
	}
	return atomicfile.WriteFile(f.path, append(data, '\n'), 0o644)
}

// Read returns the last snapshot the agent wrote.
func (f *File) Read() (agent.Snapshot, error) {
	data, err := os.ReadFile(f.path)
	if err != nil {
		return agent.Snapshot{}, fmt.Errorf("read agent status: %w", err)
	}
	var dto snapshotDTO
	if err := json.Unmarshal(data, &dto); err != nil {
		return agent.Snapshot{}, fmt.Errorf("decode agent status %s: %w", f.path, err)
	}
	return fromDTO(dto)
}

type snapshotDTO struct {
	ConfigValid   bool               `json:"config_valid"`
	PolicyApplied bool               `json:"policy_applied"`
	ListsCurrent  bool               `json:"lists_current"`
	Mode          string             `json:"mode"`
	Exits         []exitDTO          `json:"exits"`
	Lists         map[string]listDTO `json:"lists"`
	Guard         guardDTO           `json:"guard"`
	Resolver      resolverDTO        `json:"resolver"`
	Counters      map[string]uint64  `json:"counters"`
	ApplyErrors   uint64             `json:"apply_errors"`
	Drift         uint64             `json:"drift"`
	LastReconcile time.Time          `json:"last_reconcile"`
}

type exitDTO struct {
	Name    string `json:"name"`
	Slot    int    `json:"slot"`
	Present bool   `json:"present"`
	Healthy bool   `json:"healthy"`
	Alert   bool   `json:"alert"`
}

type listDTO struct {
	Entries        int     `json:"entries"`
	RefreshSeconds float64 `json:"refresh_seconds,omitempty"`
	AgeSeconds     float64 `json:"age_seconds,omitempty"`
	Missing        bool    `json:"missing,omitempty"`
	Failed         bool    `json:"failed,omitempty"`
}

type guardDTO struct {
	Mode    string            `json:"mode"`
	Refused map[string]uint64 `json:"refused,omitempty"`
}

type resolverDTO struct {
	Enabled bool `json:"enabled"`
	Up      bool `json:"up"`
}

func toDTO(s agent.Snapshot) snapshotDTO {
	dto := snapshotDTO{
		ConfigValid:   s.ConfigValid,
		PolicyApplied: s.PolicyApplied,
		ListsCurrent:  s.ListsCurrent,
		Mode:          s.Mode.String(),
		Exits:         make([]exitDTO, 0, len(s.Exits)),
		Lists:         map[string]listDTO{},
		Guard:         guardDTO{Mode: s.Guard.Mode.String(), Refused: s.Guard.Refused},
		Resolver:      resolverDTO{Enabled: s.Resolver.Enabled, Up: s.Resolver.Up},
		Counters:      s.Counters,
		ApplyErrors:   s.ApplyErrors,
		Drift:         s.Drift,
		LastReconcile: s.LastReconcile,
	}
	for _, e := range s.Exits {
		dto.Exits = append(dto.Exits, exitDTO{Name: e.Name, Slot: e.Slot, Present: e.Present, Healthy: e.Healthy, Alert: e.Alert})
	}
	for name, l := range s.Lists {
		dto.Lists[name] = listDTO{
			Entries:        l.Entries,
			RefreshSeconds: l.Refresh.Seconds(),
			AgeSeconds:     l.Age.Seconds(),
			Missing:        l.Missing,
			Failed:         l.Failed,
		}
	}
	return dto
}

func fromDTO(dto snapshotDTO) (agent.Snapshot, error) {
	s := agent.Snapshot{
		ConfigValid:   dto.ConfigValid,
		PolicyApplied: dto.PolicyApplied,
		ListsCurrent:  dto.ListsCurrent,
		Resolver:      agent.ResolverSnapshot{Enabled: dto.Resolver.Enabled, Up: dto.Resolver.Up},
		Counters:      dto.Counters,
		ApplyErrors:   dto.ApplyErrors,
		Drift:         dto.Drift,
		LastReconcile: dto.LastReconcile,
	}
	var err error
	if s.Mode, err = parseMode(dto.Mode); err != nil {
		return agent.Snapshot{}, err
	}
	if s.Guard.Mode, err = parseMode(dto.Guard.Mode); err != nil {
		return agent.Snapshot{}, err
	}
	s.Guard.Refused = dto.Guard.Refused
	if len(dto.Lists) > 0 {
		s.Lists = map[string]agent.ListStatus{}
	}
	for name, l := range dto.Lists {
		s.Lists[name] = agent.ListStatus{
			Entries: l.Entries,
			Refresh: seconds(l.RefreshSeconds),
			Age:     seconds(l.AgeSeconds),
			Missing: l.Missing,
			Failed:  l.Failed,
		}
	}
	for _, e := range dto.Exits {
		s.Exits = append(s.Exits, exits.Status{Name: e.Name, Slot: e.Slot, Present: e.Present, Healthy: e.Healthy, Alert: e.Alert})
	}
	return s, nil
}

// parseMode reads a mode; the empty string is a snapshot taken before any
// valid policy was read.
func parseMode(name string) (policy.Mode, error) {
	if name == "" || name == policy.ModeUnknown.String() {
		return policy.ModeUnknown, nil
	}
	mode, ok := policy.ParseMode(name)
	if !ok {
		return policy.ModeUnknown, fmt.Errorf("agent status: unknown mode %q", name)
	}
	return mode, nil
}

func seconds(s float64) time.Duration { return time.Duration(s * float64(time.Second)) }
