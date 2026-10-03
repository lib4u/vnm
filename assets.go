// Package vnm holds the files the vnm binary installs onto a node, embedded so
// that the installer puts down exactly what the tests checked — no loose files
// next to the binary. The units are text/template sources over install.Layout:
// the installer fills in every path.
package vnm

import _ "embed"

// DefaultConfig is the fleet node's policy template (configs/vnm.yaml).
//
//go:embed configs/vnm.yaml
var DefaultConfig []byte

// BootUnit restores the last good state before the network comes up.
//
//go:embed init/vnm-boot.service
var BootUnit []byte

// AgentUnit runs the control loop.
//
//go:embed init/vnm-agent.service
var AgentUnit []byte

// DNSUnit runs the resolver behind the domain lists.
//
//go:embed init/vnm-dns.service
var DNSUnit []byte

// NDPIUnit runs nDPId for the p2p part, once its binary is placed.
//
//go:embed init/vnm-ndpid.service
var NDPIUnit []byte
