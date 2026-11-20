// Package addrs groups IPv4 addresses for limits and classifies their scope. v0.1.x is IPv4 only: any other address,
// an IPv4-mapped one included, is Invalid.
package addrs

import "net/netip"

var (
	cgnat       = netip.MustParsePrefix("100.64.0.0/10")
	thisNetwork = netip.MustParsePrefix("0.0.0.0/8")
	reserved    = netip.MustParsePrefix("240.0.0.0/4")
)

// Scope is how far an address is reachable.
type Scope int

// The scopes, from the narrowest.
const (
	Invalid Scope = iota
	Loopback
	LinkLocal
	Private
	Global
)

// IPv4 reports whether ap is an IPv4 address; an IPv4-mapped IPv6 address is not.
func IPv4(ap netip.AddrPort) bool { return ap.Addr().Is4() }

// Host returns the /32 of an IPv4 address, the unit of per-host limits; any other address has none (the zero Prefix).
func Host(ip netip.Addr) netip.Prefix {
	if !ip.Is4() {
		return netip.Prefix{}
	}
	return netip.PrefixFrom(ip, 32)
}

// Group returns the /24 of an IPv4 address, which counts as one network; any other address has none (the zero Prefix).
func Group(ip netip.Addr) netip.Prefix {
	if !ip.Is4() {
		return netip.Prefix{}
	}
	return netip.PrefixFrom(ip, 24).Masked()
}

// Wide returns the /16 of an IPv4 address: servers in two of them count as independent witnesses of a peer's IP; any
// other address has none (the zero Prefix).
func Wide(ip netip.Addr) netip.Prefix {
	if !ip.Is4() {
		return netip.Prefix{}
	}
	return netip.PrefixFrom(ip, 16).Masked()
}

// ScopeOf returns the scope of ip. Non-IPv4, unspecified, multicast, 0.0.0.0/8 and 240.0.0.0/4 (with 255.255.255.255)
// addresses are Invalid. The documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), 192.0.0.0/24 and
// the benchmarking range 198.18.0.0/15 are Global on purpose: the simulator and the tests use them as public addresses.
func ScopeOf(ip netip.Addr) Scope {
	switch {
	case !ip.Is4(), ip.IsUnspecified(), ip.IsMulticast(), thisNetwork.Contains(ip), reserved.Contains(ip):
		return Invalid
	case ip.IsLoopback():
		return Loopback
	case ip.IsLinkLocalUnicast():
		return LinkLocal
	case ip.IsPrivate(), cgnat.Contains(ip):
		return Private
	}
	return Global
}

// Usable reports whether a packet may be sent to ap: a valid unicast IPv4 address and a non-zero port.
func Usable(ap netip.AddrPort) bool {
	return ap.Port() != 0 && ScopeOf(ap.Addr()) != Invalid
}

// AllowedFrom reports whether an address learned from a node at from may be used:
// it must be usable, and global or in the same scope as from, so a public node cannot point us into our own network.
func AllowedFrom(entry netip.AddrPort, from netip.Addr) bool {
	if !Usable(entry) {
		return false
	}
	s := ScopeOf(entry.Addr())
	return s == Global || s == ScopeOf(from)
}
