// Package sockets finds the ports the node serves on, for the listen-port
// safety net of ТЗ §3.4: a new connection leaving from one of them is a server
// answering a client whose conntrack entry expired, not a connection the node
// opens.
//
// The set must not include client sockets, or their traffic would bypass the
// policy — a leak. TCP is unambiguous: a listening socket. UDP is not: an
// outbound UDP socket that was never connected looks like a server. Such
// sockets get their port from the ephemeral range, so UDP ports inside that
// range are left out; services listen on fixed ports below it.
package sockets

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/lib4u/vnm/internal/domain/netstate"
)

// Socket states in /proc/net/{tcp,udp}.
const (
	stateTCPListen      = "0A"
	stateUDPUnconnected = "07"
)

// Reader reads the socket tables of the current network namespace.
type Reader struct {
	// proc is the procfs mount, injectable for tests.
	proc string
}

// NewReader returns a Reader over the procfs mounted at proc.
func NewReader(proc string) *Reader {
	return &Reader{proc: proc}
}

// Listening returns the ports served on, per transport.
func (r *Reader) Listening() (netstate.Ports, error) {
	low, high, err := r.ephemeralRange()
	if err != nil {
		return netstate.Ports{}, err
	}
	var ports netstate.Ports
	for _, name := range []string{"tcp", "tcp6"} {
		got, err := r.scan(name, func(state string, port uint16, remoteSet bool) bool {
			return state == stateTCPListen
		})
		if err != nil {
			return netstate.Ports{}, err
		}
		ports.TCP = append(ports.TCP, got...)
	}
	for _, name := range []string{"udp", "udp6"} {
		got, err := r.scan(name, func(state string, port uint16, remoteSet bool) bool {
			ephemeral := port >= low && port <= high
			return state == stateUDPUnconnected && !remoteSet && !ephemeral
		})
		if err != nil {
			return netstate.Ports{}, err
		}
		ports.UDP = append(ports.UDP, got...)
	}
	slices.Sort(ports.TCP)
	slices.Sort(ports.UDP)
	return netstate.Ports{TCP: slices.Compact(ports.TCP), UDP: slices.Compact(ports.UDP)}, nil
}

// scan returns the local ports of the table entries keep accepts.
func (r *Reader) scan(table string, keep func(state string, port uint16, remoteSet bool) bool) ([]uint16, error) {
	data, err := os.ReadFile(filepath.Join(r.proc, "net", table))
	if os.IsNotExist(err) {
		return nil, nil // no IPv6 on the node
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", table, err)
	}
	var ports []uint16
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Scan() // header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 {
			return nil, fmt.Errorf("%s: short line %q", table, sc.Text())
		}
		port, err := portOf(fields[1])
		if err != nil {
			return nil, fmt.Errorf("%s: %w", table, err)
		}
		remotePort, err := portOf(fields[2])
		if err != nil {
			return nil, fmt.Errorf("%s: %w", table, err)
		}
		if keep(fields[3], port, remotePort != 0) {
			ports = append(ports, port)
		}
	}
	return ports, sc.Err()
}

// portOf parses the port of an "ADDR:PORT" hex field.
func portOf(field string) (uint16, error) {
	_, hexPort, ok := strings.Cut(field, ":")
	if !ok {
		return 0, fmt.Errorf("address %q has no port", field)
	}
	port, err := strconv.ParseUint(hexPort, 16, 16)
	if err != nil {
		return 0, fmt.Errorf("port of %q: %w", field, err)
	}
	return uint16(port), nil
}

// ephemeralRange reads the local port range outbound sockets are given.
func (r *Reader) ephemeralRange() (low, high uint16, err error) {
	data, err := os.ReadFile(filepath.Join(r.proc, "sys", "net", "ipv4", "ip_local_port_range"))
	if err != nil {
		return 0, 0, fmt.Errorf("read ephemeral port range: %w", err)
	}
	fields := strings.Fields(string(data))
	if len(fields) != 2 {
		return 0, 0, fmt.Errorf("ephemeral port range %q", data)
	}
	l, errL := strconv.ParseUint(fields[0], 10, 16)
	h, errH := strconv.ParseUint(fields[1], 10, 16)
	if errL != nil || errH != nil {
		return 0, 0, fmt.Errorf("ephemeral port range %q", data)
	}
	return uint16(l), uint16(h), nil
}
