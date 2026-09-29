// Package app wires the dependency graph of the vnm binary (manual dependency
// injection). It is the only package that knows every concrete adapter.
package app

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"path/filepath"
	"time"

	"github.com/lib4u/vnm/internal/infrastructure/configfile"
	"github.com/lib4u/vnm/internal/infrastructure/filelock"
	"github.com/lib4u/vnm/internal/infrastructure/iproute"
	"github.com/lib4u/vnm/internal/infrastructure/listcache"
	"github.com/lib4u/vnm/internal/infrastructure/metrics"
	"github.com/lib4u/vnm/internal/infrastructure/nftables"
	"github.com/lib4u/vnm/internal/infrastructure/probe"
	"github.com/lib4u/vnm/internal/infrastructure/renew"
	"github.com/lib4u/vnm/internal/infrastructure/resolver"
	"github.com/lib4u/vnm/internal/infrastructure/runner"
	"github.com/lib4u/vnm/internal/infrastructure/sockets"
	"github.com/lib4u/vnm/internal/infrastructure/statefile"
	"github.com/lib4u/vnm/internal/infrastructure/statusfile"
	"github.com/lib4u/vnm/internal/infrastructure/system"
	"github.com/lib4u/vnm/internal/infrastructure/wgcf"
	"github.com/lib4u/vnm/internal/infrastructure/wgexit"
	"github.com/lib4u/vnm/internal/usecase/agent"
	"github.com/lib4u/vnm/internal/usecase/apply"
	"github.com/lib4u/vnm/internal/usecase/doctor"
	"github.com/lib4u/vnm/internal/usecase/exits"
	"github.com/lib4u/vnm/internal/usecase/inspect"
	"github.com/lib4u/vnm/internal/usecase/install"
	"github.com/lib4u/vnm/internal/usecase/lists"
	"github.com/lib4u/vnm/internal/usecase/modeswitch"
)

const (
	// commandTimeout caps one nft or ip call; a wedged tool must not hang the
	// agent.
	commandTimeout = 30 * time.Second
	// lockWait is how long a pass waits for the CLI to finish a change.
	lockWait = 30 * time.Second
	// downloadTimeout caps one list download.
	downloadTimeout = 2 * time.Minute
	// renewTimeout bounds an exit's renew command: a registration with its
	// retries. The agent's pass waits for it.
	renewTimeout = 2 * time.Minute
	// installCommandTimeout covers apt waiting for the dpkg lock.
	installCommandTimeout = 20 * time.Minute
)

// Paths are the files and directories the binary uses.
type Paths struct {
	Binary   string
	UnitDir  string
	ToolDir  string
	Config   string
	StateDir string
	Lock     string
	Metrics  string
	Proc     string
}

// DefaultPaths are the locations on a node.
var DefaultPaths = Paths{
	Binary:   "/usr/local/bin/vnm",
	UnitDir:  "/etc/systemd/system",
	ToolDir:  "/usr/local/lib/vnm",
	Config:   "/etc/vnm/config.yaml",
	StateDir: "/var/lib/vnm",
	Lock:     "/run/vnm/state.lock",
	Metrics:  "/var/lib/node_exporter/textfile_collector/vnm.prom",
	Proc:     "/proc",
}

// Names of the path flags every command accepts.
const (
	flagConfig   = "config"
	flagStateDir = "state-dir"
	flagLock     = "lock"
	flagMetrics  = "metrics"
)

// Bind registers the path overrides on a command's flags.
func (p *Paths) Bind(fs *flag.FlagSet) {
	fs.StringVar(&p.Config, flagConfig, p.Config, "policy file")
	fs.StringVar(&p.StateDir, flagStateDir, p.StateDir, "state directory")
	fs.StringVar(&p.Lock, flagLock, p.Lock, "state lock shared by the agent and the CLI")
	fs.StringVar(&p.Metrics, flagMetrics, p.Metrics, "node_exporter textfile")
}

// Args are the path flags that give another vnm command the same paths.
func (p Paths) Args() []string {
	return []string{
		"-" + flagConfig, p.Config,
		"-" + flagStateDir, p.StateDir,
		"-" + flagLock, p.Lock,
		"-" + flagMetrics, p.Metrics,
	}
}

// Layout is the installer's view of the paths.
func (p Paths) Layout() install.Layout {
	return install.Layout{Binary: p.Binary, UnitDir: p.UnitDir, Config: p.Config, StateDir: p.StateDir, ConfigMode: configMode}
}

// configMode is the policy file's mode, whoever writes it: it holds no
// secrets, and one mode keeps the writers from flipping it back and forth.
const configMode = 0o644

// NewInstaller wires the installer. exitConf is the conf path of the policy's
// WARP exit; its WARP account lives in the same directory.
func (p Paths) NewInstaller(exitConf string) *install.Installer {
	run := runner.System{Timeout: installCommandTimeout}
	warp := wgcf.New(run, &http.Client{Timeout: downloadTimeout},
		filepath.Join(p.ToolDir, "wgcf"), filepath.Dir(exitConf), exitConf)
	return p.installer(run, warp)
}

// NewBaseInstaller wires the installer for the base part alone: SSH,
// fail2ban, sysctl and swap need neither a policy nor WARP, so a broken
// policy cannot keep an operator from confirming the SSH change in time.
func (p Paths) NewBaseInstaller() *install.Installer {
	return p.installer(runner.System{Timeout: installCommandTimeout}, nil)
}

func (p Paths) installer(run runner.Runner, warp install.Warp) *install.Installer {
	sys := system.New(run)
	return install.New(install.Deps{
		Files: sys, Packages: sys, Services: sys, Host: sys,
		Warp:  warp,
		Rules: iproute.NewRouter(run),
	})
}

// Locker returns the state lock shared by the agent and the CLI.
func (p Paths) Locker() filelock.Locker {
	return filelock.Locker{Path: p.Lock, Wait: lockWait}
}

// Applier returns the kernel side alone: nft, ip and the last good state. The
// boot unit runs with only this, before the network exists.
func (p Paths) Applier() (*apply.Applier, *nftables.Firewall) {
	run := runner.System{Timeout: commandTimeout}
	fw := nftables.NewFirewall(run)
	return apply.New(fw, iproute.NewRouter(run), statefile.New(p.StateDir)), fw
}

// Status is the agent's last snapshot, which the CLI reports.
func (p Paths) Status() *statusfile.File {
	return statusfile.New(filepath.Join(p.StateDir, "status.json"))
}

// Inspector explains destinations from the applied state and the live table.
func (p Paths) Inspector() *inspect.Inspector {
	return inspect.New(nftables.NewFirewall(runner.System{Timeout: commandTimeout}), statefile.New(p.StateDir))
}

// ModeSwitch wires the mode switch of the egress and the guard. The policy a
// provisional switch replaced is kept beside the lock, on /run: it must not
// outlive the rollback timer.
func (p Paths) ModeSwitch() *modeswitch.Switcher {
	sys := system.New(runner.System{Timeout: commandTimeout})
	return modeswitch.New(modeswitch.Deps{
		Files:     sys,
		Policy:    configfile.Format{},
		Scheduler: sys,
		Lock:      p.Locker(),
		Paths: modeswitch.Paths{
			Config:     p.Config,
			ConfigMode: configMode,
			Previous:   filepath.Join(filepath.Dir(p.Lock), "mode-previous.yaml"),
			Binary:     p.Binary,
			Args:       p.Args(),
		},
	})
}

// Doctor wires the node checks.
func (p Paths) Doctor() *doctor.Doctor {
	applier, _ := p.Applier()
	sys := system.New(runner.System{Timeout: commandTimeout})
	return doctor.New(doctor.Deps{
		Config:   configfile.NewSource(p.Config),
		Status:   p.Status(),
		Units:    sys,
		Kernel:   applier,
		Store:    statefile.New(p.StateDir),
		Forward:  sys,
		Firewall: sys,
		Files:    sys,
		Now:      time.Now,
	})
}

// ListRefresher downloads the policy's remote list sources into the local
// copies the agent reads. Each node draws its own spread, so a fleet
// installed at once does not download at once.
func (p Paths) ListRefresher() *lists.Remote {
	return p.listRemote(p.listCache())
}

func (p Paths) listRemote(cache *listcache.Cache) *lists.Remote {
	return lists.NewRemote(cache, time.Now, rand.Float64()*lists.MaxSpread)
}

func (p Paths) listCache() *listcache.Cache {
	return listcache.New(filepath.Join(p.StateDir, "lists"), &http.Client{Timeout: downloadTimeout})
}

// publishers hands every snapshot to each of its publishers.
type publishers []agent.Metrics

func (ps publishers) Publish(s agent.Snapshot) error {
	var errs []error
	for _, p := range ps {
		errs = append(errs, p.Publish(s))
	}
	return errors.Join(errs...)
}

// Agent is the wired control loop and what must be closed with it.
type Agent struct {
	*agent.Agent
	device *wgexit.Device
}

// Close releases the WireGuard control socket.
func (a *Agent) Close() error {
	return a.device.Close()
}

// NewAgent wires the control loop.
func NewAgent(p Paths, log *slog.Logger) (*Agent, error) {
	run := runner.System{Timeout: commandTimeout}
	applier, fw := p.Applier()

	device, err := wgexit.NewDevice(run, filepath.Join(p.Proc, "sys"))
	if err != nil {
		return nil, fmt.Errorf("exits: %w", err)
	}
	cache := p.listCache()
	router := iproute.NewRouter(run)

	loop := agent.New(agent.Deps{
		Config:    configfile.NewSource(p.Config),
		Kernel:    applier,
		Store:     statefile.New(p.StateDir),
		Counters:  fw,
		Exits:     exits.NewSupervisor(device, probe.New(), renew.New(runner.System{Timeout: renewTimeout}), time.Now),
		Lists:     lists.NewResolver(cache),
		Resolver:  resolver.New(p.Layout().ResolverConf(), run),
		Refresher: p.listRemote(cache),
		Uplinks:   router,
		Listening: sockets.NewReader(p.Proc),
		Lock:      p.Locker(),
		Metrics:   publishers{metrics.NewTextfile(p.Metrics), p.Status()},
		Log:       log,
		Now:       time.Now,
	})
	return &Agent{Agent: loop, device: device}, nil
}
