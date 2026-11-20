package kolodht

import (
	"crypto/ed25519"
	"net/netip"
	"slices"
)

// Topic is a 32-byte value peers announce and look up, such as a hash of an application's topic name.
type Topic [32]byte

// Record is a peer found on a topic: its kolo-id key and address, signed by that key and verified by Lookup.
// It also holds the servers that stored it, which Connect uses as relays.
type Record struct {
	// Topic is the topic the peer announced.
	Topic Topic
	// PublicKey is the peer's kolo-id public key.
	PublicKey ed25519.PublicKey
	// Addr is the peer's address as the freshest server stored it.
	Addr   netip.AddrPort
	relays []relay
}

// relay is a server that returned a record, with our token there and the peer's address as it stored it. confirmed
// means servers in two /16s, among the K closest answers to our lookup, stored the record at addr's IP.
type relay struct {
	server    netip.AddrPort
	token     [32]byte
	addr      netip.AddrPort
	age       uint16
	confirmed bool
}

// Addrs returns every address Connect may probe or dial for r: Addr and each relay's stored peer address, once each,
// IPv4 only. Random-port probes go to the IPs of these addresses.
func (r Record) Addrs() []netip.AddrPort {
	var out []netip.AddrPort
	add := func(a netip.AddrPort) {
		if a.Addr().Is4() && !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	add(r.Addr)
	for _, rl := range r.relays {
		add(rl.addr)
	}
	return out
}
