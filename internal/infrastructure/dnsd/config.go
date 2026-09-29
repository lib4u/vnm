// Package dnsd is the vnm resolver (docs/vpn-node-manager-dns-tz.md): it
// answers the DNS the kernel redirects to it by forwarding to the upstreams,
// and before an answer for a listed domain leaves, puts its addresses into the
// list's sets. It runs as `vnm dns serve` under vnm-dns.service, apart from
// the agent, which writes its config.
package dnsd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
)

// Config is what the agent tells the resolver (dns ТЗ §3.4). Set names are the
// kernel's: the resolver knows nothing of how the table names them.
type Config struct {
	Port      uint16           `json:"port"`
	Upstreams []netip.AddrPort `json:"upstreams"`
	// Uplinks are the interfaces a query must never be answered on.
	Uplinks []string    `json:"uplinks"`
	Sets    []DomainSet `json:"sets"`
}

// DomainSet is a list's domains and the sets their addresses go into.
type DomainSet struct {
	Set4    string   `json:"set4"`
	Set6    string   `json:"set6"`
	Domains []string `json:"domains"`
	// NoAAAA drops IPv6 addresses from answers for these domains: their IPv6
	// is blocked while their IPv4 reaches them (dns ТЗ §3.3a).
	NoAAAA bool `json:"no_aaaa,omitempty"`
}

// Encode returns the config as the resolver reads it.
func (c Config) Encode() ([]byte, error) {
	data, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("encode resolver config: %w", err)
	}
	return append(data, '\n'), nil
}

// Load reads and checks a config; "-" reads it from standard input, which is
// how the unit passes it: systemd opens the file as root, and the resolver's
// user needs no access to the agent's state directory.
func Load(path string) (Config, error) {
	var data []byte
	var err error
	if path == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return Config{}, err
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return Config{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := c.validate(); err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

func (c Config) validate() error {
	var errs []error
	if c.Port == 0 {
		errs = append(errs, errors.New("no port"))
	}
	if len(c.Upstreams) == 0 {
		errs = append(errs, errors.New("no upstreams"))
	}
	for i, s := range c.Sets {
		if s.Set4 == "" || s.Set6 == "" {
			errs = append(errs, fmt.Errorf("set %d: a set of each family is required", i))
		}
	}
	return errors.Join(errs...)
}
