package agent

import (
	"context"
	"github.com/lib4u/vnm/internal/usecase/p2pwatch"
	"time"

	"github.com/lib4u/vnm/internal/domain/netstate"
	"github.com/lib4u/vnm/internal/domain/policy"
	"github.com/lib4u/vnm/internal/usecase/exits"
	"github.com/lib4u/vnm/internal/usecase/lists"
)

// ConfigSource loads the node's policy. Version identifies the content, so the
// agent re-resolves lists only when the policy actually changed.
type ConfigSource interface {
	Load() (cfg policy.Config, version string, err error)
}

// Kernel applies states.
type Kernel interface {
	Apply(ctx context.Context, s netstate.State) error
	Verify(ctx context.Context, s netstate.State) error
	SetHealth(ctx context.Context, h netstate.Health) error
}

// Store holds the last state applied and verified.
type Store interface {
	LastGood() (s netstate.State, ok bool, err error)
}

// Counters reads the classification counters of the applied ruleset.
type Counters interface {
	Counters(ctx context.Context) (map[string]uint64, error)
}

// ExitChecker checks and heals the exits.
type ExitChecker interface {
	Check(ctx context.Context, cfg policy.Config) ([]exits.Status, error)
	// Retire removes the interface of an exit no longer in the policy.
	Retire(ctx context.Context, iface string) error
}

// ListResolver resolves lists from local data.
type ListResolver interface {
	Resolve(ctx context.Context, cfg policy.Config, previous map[string]lists.Sizes) (lists.Resolved, error)
	Domains(ctx context.Context, cfg policy.Config) (map[string][]string, error)
}

// Resolver runs the resolver that fills the domain lists' sets.
type Resolver interface {
	Apply(ctx context.Context, s netstate.State) error
	// Up reports whether the resolver answers on the port.
	Up(ctx context.Context, port uint16) bool
	// UID is the user the resolver queries its upstreams as.
	UID() (uint32, error)
}

// ListRefresher refreshes the local copies of remote list sources.
type ListRefresher interface {
	// Refresh downloads the copies that are due.
	Refresh(ctx context.Context, cfg policy.Config) error
	// Copies returns the local copy of every remote source, keyed by URL.
	Copies(cfg policy.Config) map[string]lists.Copy
}

// Uplinks detects the interfaces of the default route.
type Uplinks interface {
	Uplinks(ctx context.Context) ([]string, error)
}

// Listening reads the ports the node serves on.
type Listening interface {
	Listening() (netstate.Ports, error)
}

// Locker serialises state changes with the CLI.
type Locker interface {
	Lock(ctx context.Context) (release func() error, err error)
}

// Metrics publishes the agent's state.
type Metrics interface {
	Publish(s Snapshot) error
}

// ListStatus is one list as the agent sees it.
type ListStatus struct {
	// Entries are its address ranges in the applied state.
	Entries int
	// Refresh is how old its remote copies may get; zero when it reads
	// nothing remote.
	Refresh time.Duration
	// Age is the age of its oldest remote copy.
	Age time.Duration
	// Missing means a remote source of it has no local copy at all: the list
	// is not merely old, it never arrived.
	Missing bool
	// Failed means its last resolution failed; a guard list then keeps its
	// previous ranges or guards nothing.
	Failed bool
}

// GuardSnapshot is the guard as the agent sees it.
type GuardSnapshot struct {
	Mode policy.Mode
	// Refused counts, per list, the packets of new connections the guard
	// refused — in observe, would have refused. A refused connection is
	// never established, so each retransmitted attempt counts again.
	Refused map[string]uint64
}

// P2PSnapshot is the p2p part as the agent sees it.
type P2PSnapshot struct {
	Mode policy.Mode
	// Refused counts, per signature, the packets the kernel refused — in
	// observe, would have refused.
	Refused map[string]uint64
	// NDPI is the classifier's side (p2p ТЗ §3.3): whether the policy uses
	// it, whether nDPId writes to the socket, and what the watcher did.
	NDPI       bool
	Connected  bool
	Detections uint64
	Peers      uint64
	Bans       uint64
}

// P2PWatch acts on nDPI's verdicts beside the loop (p2p ТЗ §3.3–3.4).
type P2PWatch interface {
	// Update gives it the policy's p2p part and whether the kernel holds it.
	Update(ctx context.Context, p policy.P2P, applied bool)
	Stats() p2pwatch.Stats
}

// ResolverSnapshot is the resolver as the applied state has it.
type ResolverSnapshot struct {
	// Enabled means the policy uses domain lists, so a resolver is wanted.
	Enabled bool
	// Up means DNS is redirected to it: it answered on the last check.
	Up bool
}

// Snapshot is the agent's state after a pass, for monitoring (ТЗ §7.5).
type Snapshot struct {
	ConfigValid bool
	// PolicyApplied means the kernel holds the policy in the file: planned
	// with its own lists and applied.
	PolicyApplied bool
	// ListsCurrent is false while the lists in force are older than the local
	// copies, because the copies did not resolve.
	ListsCurrent  bool
	Mode          policy.Mode
	Exits         []exits.Status
	Lists         map[string]ListStatus
	Guard         GuardSnapshot
	P2P           P2PSnapshot
	Resolver      ResolverSnapshot
	Counters      map[string]uint64
	ApplyErrors   uint64
	Drift         uint64
	LastReconcile time.Time
}
