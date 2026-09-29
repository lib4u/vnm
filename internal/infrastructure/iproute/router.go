package iproute

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"slices"

	"github.com/lib4u/vnm/internal/domain/netstate"
	"github.com/lib4u/vnm/internal/infrastructure/runner"
	"github.com/lib4u/vnm/internal/usecase/apply"
)

// Router applies the routing side of the state through the ip tool.
type Router struct {
	run runner.Runner
	// conf is the root ip reads its configuration under.
	conf fs.FS
}

var _ apply.Router = (*Router)(nil)

// Option configures a Router.
type Option func(*Router)

// WithConfigRoot reads ip's configuration — the names of routing tables —
// under conf instead of the host's root.
func WithConfigRoot(conf fs.FS) Option {
	return func(r *Router) { r.conf = conf }
}

// NewRouter returns a Router that runs ip through r.
func NewRouter(r runner.Runner, opts ...Option) *Router {
	rt := &Router{run: r, conf: os.DirFS("/")}
	for _, opt := range opts {
		opt(rt)
	}
	return rt
}

// tableNames resolves table names for one listing.
func (r *Router) tableNames() *tableNames {
	return &tableNames{conf: r.conf}
}

// Rules returns the IPv4 rules in the owned priority range.
func (r *Router) Rules(ctx context.Context) ([]netstate.IPRule, error) {
	out, err := r.ip(ctx, "-j", "rule", "show")
	if err != nil {
		return nil, err
	}
	var raw []ruleEntry
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		return nil, fmt.Errorf("parse ip rule output: %w", err)
	}

	tables := r.tableNames()
	var rules []netstate.IPRule
	for _, e := range raw {
		priority, err := e.priority()
		if err != nil {
			return nil, fmt.Errorf("rule: %w", err)
		}
		if priority < netstate.OwnedPriorities[0] || priority > netstate.OwnedPriorities[1] {
			continue
		}
		parsed, err := parseRule(e, tables)
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", priority, err)
		}
		rules = append(rules, parsed)
	}
	return rules, nil
}

// AddRule adds a rule.
func (r *Router) AddRule(ctx context.Context, rl netstate.IPRule) error {
	_, err := r.ip(ctx, append([]string{"rule", "add"}, RuleArgs(rl)...)...)
	return err
}

// DeleteRule deletes exactly the given rule: its arguments name every
// selector the rule has, so the kernel cannot match another rule of the same
// priority — the agent's own among them — in its place.
func (r *Router) DeleteRule(ctx context.Context, rl netstate.IPRule) error {
	_, err := r.ip(ctx, append([]string{"rule", "del"}, RuleArgs(rl)...)...)
	return err
}

// Routes returns the default routes of the owned tables, from one listing of
// all tables: asking ip for a table that was never created is an error rather
// than an empty answer, and one dump beats one per table.
func (r *Router) Routes(ctx context.Context) ([]netstate.Route, error) {
	raw, err := r.routes(ctx, "-4", "-j", "route", "show", "table", "all")
	if err != nil {
		return nil, err
	}
	owned, tables := netstate.OwnedTables(), r.tableNames()
	var routes []netstate.Route
	for _, e := range raw {
		if e.Dst != "default" {
			continue
		}
		table, known, err := tables.id(e.Table)
		if err != nil {
			return nil, err
		}
		if !known || !slices.Contains(owned, table) {
			continue // a foreign table
		}
		routes = append(routes, parseRoute(e, table))
	}
	return routes, nil
}

// Uplinks returns the interfaces of the main table's IPv4 default routes,
// including the nexthops of a multipath route or a nexthop group, in the
// order ip lists them.
func (r *Router) Uplinks(ctx context.Context) ([]string, error) {
	raw, err := r.routes(ctx, "-4", "-j", "route", "show", "default")
	if err != nil {
		return nil, err
	}
	var devs []string
	add := func(dev string) {
		if dev != "" && !slices.Contains(devs, dev) {
			devs = append(devs, dev)
		}
	}
	for _, e := range raw {
		add(e.Dev)
		for _, nh := range e.Nexthops {
			add(nh.Dev)
		}
	}
	return devs, nil
}

// ReplaceRoute sets a table's default route.
func (r *Router) ReplaceRoute(ctx context.Context, rt netstate.Route) error {
	_, err := r.ip(ctx, append([]string{"route", "replace"}, RouteArgs(rt)...)...)
	return err
}

// DeleteRoute deletes exactly the given default route, by everything that
// tells it apart.
func (r *Router) DeleteRoute(ctx context.Context, rt netstate.Route) error {
	_, err := r.ip(ctx, append([]string{"route", "del"}, RouteArgs(rt)...)...)
	return err
}

func (r *Router) routes(ctx context.Context, args ...string) ([]route, error) {
	out, err := r.ip(ctx, args...)
	if err != nil {
		return nil, err
	}
	var raw []route
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		return nil, fmt.Errorf("parse ip route output: %w", err)
	}
	return raw, nil
}

func (r *Router) ip(ctx context.Context, args ...string) (string, error) {
	return r.run.Run(ctx, runner.Command{Name: "ip", Args: args})
}
