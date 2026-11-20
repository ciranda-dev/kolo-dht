package kolodht

import (
	"net/netip"
	"slices"
)

// publicServers are the public entry nodes, IPv4 host:port, public data only. To add or remove one, edit this list.
var publicServers = []netip.AddrPort{
	netip.MustParseAddrPort("77.237.240.162:7447"),
	netip.MustParseAddrPort("35.212.161.205:7447"),
}

// PublicServers returns a copy of the built-in public entry nodes, the servers Bootstrap uses when it is given nil,
// so a node that bootstraps from them tells them its IP address.
func PublicServers() []netip.AddrPort {
	return slices.Clone(publicServers)
}
