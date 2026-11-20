package kolodht

import (
	"fmt"
	"net"
	"net/netip"
)

// TraceKind says what a TraceEvent reports.
type TraceKind int

const (
	// TraceProbeSent: a probe of Size bytes left Local for Remote, at TTL (0 is the system default).
	TraceProbeSent TraceKind = iota + 1
	// TraceProbeReceived: a probe of Size bytes for a punch of ours reached Local from Remote.
	TraceProbeReceived
	// TraceBirthdayOpened: Count sockets, the node's own included, now probe Remote (birthday punch).
	TraceBirthdayOpened
	// TraceRandomProbes: up to Count probes to random ports of Remote's IP start (Remote's port is 0).
	TraceRandomProbes
	// TraceProved: Remote echoed our nonce to Local, so the punch may dial it.
	TraceProved
)

var traceNames = [...]string{"", "probe sent", "probe received", "birthday opened", "random probes", "proved"}

// String returns the name of k.
func (k TraceKind) String() string {
	if k > 0 && int(k) < len(traceNames) {
		return traceNames[k]
	}
	return fmt.Sprintf("TraceKind(%d)", int(k))
}

// TraceEvent is one step of a punch, passed to Config.Trace. Which fields are set depends on Kind.
type TraceEvent struct {
	// Kind is the step; the fields below are set as its constant says.
	Kind TraceKind
	// Local and Remote are the local socket address and the peer address.
	Local, Remote netip.AddrPort
	// Size is the probe size in bytes and TTL its IP TTL (0 is the system default).
	Size, TTL int
	// Count is the number of sockets or probes.
	Count int
}

// String formats e as one log line.
func (e TraceEvent) String() string {
	switch e.Kind {
	case TraceProbeSent:
		s := fmt.Sprintf("Sending %db to %s from port %d", e.Size, e.Remote, e.Local.Port())
		if e.TTL != 0 {
			s += fmt.Sprintf(" (TTL %d)", e.TTL)
		}
		return s
	case TraceProbeReceived:
		return fmt.Sprintf("Received %db from %s on port %d", e.Size, e.Remote, e.Local.Port())
	case TraceBirthdayOpened:
		return fmt.Sprintf("Birthday punch: %d sockets probe %s", e.Count, e.Remote)
	case TraceRandomProbes:
		return fmt.Sprintf("Random probes: up to %d to random ports of %s", e.Count, e.Remote.Addr())
	case TraceProved:
		return fmt.Sprintf("Proved %s on port %d", e.Remote, e.Local.Port())
	}
	return e.Kind.String()
}

// trace passes e to Config.Trace and drops the event if it panics. Never call it with mu held.
func (n *Node) trace(e TraceEvent) {
	if f := n.cfg.Trace; f != nil {
		defer func() { _ = recover() }()
		f(e)
	}
}

func (n *Node) localAddr() netip.AddrPort {
	if ua, ok := n.Addr().(*net.UDPAddr); ok {
		ap := ua.AddrPort()
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	}
	return netip.AddrPort{}
}
