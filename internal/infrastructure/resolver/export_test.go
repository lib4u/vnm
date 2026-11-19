package resolver

import "net/netip"

// Test hooks: the probe's retries are tested with short attempts.
var AttemptTimeout = &attemptTimeout

const ProbeAttempts = probeAttempts

// OnLoopback is where the agent probes the resolver.
func OnLoopback(port uint16) netip.AddrPort { return onLoopback(port) }
