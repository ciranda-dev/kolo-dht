package addrs

import (
	"net/netip"
	"testing"
)

func TestHostAndGroup(t *testing.T) {
	tests := []struct {
		ip, host, group string
	}{
		{"203.0.113.7", "203.0.113.7/32", "203.0.113.0/24"},
		{"10.1.2.3", "10.1.2.3/32", "10.1.2.0/24"},
	}
	for _, tt := range tests {
		ip := netip.MustParseAddr(tt.ip)
		if got := Host(ip).String(); got != tt.host {
			t.Errorf("Host(%s) = %s, want %s", tt.ip, got, tt.host)
		}
		if got := Group(ip).String(); got != tt.group {
			t.Errorf("Group(%s) = %s, want %s", tt.ip, got, tt.group)
		}
	}
}

func TestUsable(t *testing.T) {
	tests := []struct {
		ap   string
		want bool
	}{
		{"203.0.113.7:4000", true},
		{"[2001:db8::1]:4000", false},
		{"127.0.0.1:4000", true},
		{"10.0.0.1:4000", true},
		{"203.0.113.7:0", false},
		{"0.0.0.0:4000", false},
		{"[::]:4000", false},
		{"224.0.0.1:4000", false},
		{"[ff02::1]:4000", false},
		{"255.255.255.255:4000", false},
		{"0.1.2.3:4000", false},
		{"240.0.0.1:4000", false},
		{"[::ffff:0.0.0.1]:4000", false},
	}
	for _, tt := range tests {
		if got := Usable(netip.MustParseAddrPort(tt.ap)); got != tt.want {
			t.Errorf("Usable(%s) = %v, want %v", tt.ap, got, tt.want)
		}
	}
	if Usable(netip.AddrPort{}) {
		t.Error("Usable(zero) = true")
	}
}

// TestScope is the scope table that kolo-node's TestScopeTable and kolo-swarm's copy of ScopeOf must also pass: when a
// row changes here, change it there.
func TestScope(t *testing.T) {
	tests := []struct {
		ip   string
		want Scope
	}{
		{"127.0.0.1", Loopback},
		{"169.254.1.1", LinkLocal},
		{"10.1.2.3", Private},
		{"192.168.1.1", Private},
		{"172.16.0.1", Private},
		{"100.64.0.1", Private},
		{"203.0.113.7", Global},
		{"8.8.8.8", Global},
		{"198.18.0.1", Global},
		{"0.0.0.0", Invalid},
		{"0.1.2.3", Invalid},
		{"224.0.0.1", Invalid},
		{"240.0.0.1", Invalid},
		{"255.255.255.255", Invalid},
		{"::1", Invalid},
	}
	for _, tt := range tests {
		if got := ScopeOf(netip.MustParseAddr(tt.ip)); got != tt.want {
			t.Errorf("ScopeOf(%s) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

func TestAllowedFrom(t *testing.T) {
	pub := netip.MustParseAddr("203.0.113.1")
	lan := netip.MustParseAddr("192.168.1.1")
	lo := netip.MustParseAddr("127.0.0.1")
	tests := []struct {
		entry string
		from  netip.Addr
		want  bool
	}{
		{"198.51.100.2:4000", pub, true},
		{"198.51.100.2:4000", lan, true},
		{"198.51.100.2:4000", lo, true},
		{"192.168.1.9:4000", pub, false},
		{"127.0.0.1:4000", pub, false},
		{"127.0.0.1:4001", lo, true},
		{"192.168.1.9:4000", lan, true},
		{"127.0.0.1:4000", lan, false},
		{"10.0.0.1:0", lan, false},
		{"224.0.0.1:4000", pub, false},
	}
	for _, tt := range tests {
		if got := AllowedFrom(netip.MustParseAddrPort(tt.entry), tt.from); got != tt.want {
			t.Errorf("AllowedFrom(%s, %s) = %v, want %v", tt.entry, tt.from, got, tt.want)
		}
	}
}

// TestIPv6Refused checks that v0.1.x is IPv4 only: every IPv6 address, NAT64 and 6to4 included, is Invalid and
// unusable, and has no host or group; so is an IPv4-mapped address.
func TestIPv6Refused(t *testing.T) {
	pub := netip.MustParseAddr("203.0.113.1")
	for _, s := range []string{
		"::1", "fe80::1", "fe80::1%eth0", "fd00::1", "2001:db8::1", "2606:4700::1111",
		"64:ff9b::808:808", "64:ff9b::7f00:1", "64:ff9b:1::808:808", "2002:808:808::1", "2001::1",
		"::ffff:127.0.0.1", "::ffff:203.0.113.7", "::ffff:10.0.0.1",
	} {
		ip := netip.MustParseAddr(s)
		ap := netip.AddrPortFrom(ip, 4000)
		if got := ScopeOf(ip); got != Invalid {
			t.Errorf("ScopeOf(%s) = %v, want Invalid", s, got)
		}
		if Usable(ap) || AllowedFrom(ap, pub) || AllowedFrom(ap, ip) {
			t.Errorf("%s is usable", s)
		}
		if h, g := Host(ip), Group(ip); h.IsValid() || g.IsValid() {
			t.Errorf("Host(%s) = %v, Group = %v, want none", s, h, g)
		}
		if IPv4(ap) {
			t.Errorf("IPv4(%s) = true", ap)
		}
	}
	if !IPv4(netip.MustParseAddrPort("203.0.113.7:4000")) {
		t.Error("IPv4(203.0.113.7:4000) = false")
	}
	if IPv4(netip.AddrPort{}) {
		t.Error("IPv4(zero) = true")
	}
}

func TestWide(t *testing.T) {
	for in, want := range map[string]string{"198.18.7.1": "198.18.0.0/16", "203.0.113.200": "203.0.0.0/16"} {
		if got := Wide(netip.MustParseAddr(in)); got != netip.MustParsePrefix(want) {
			t.Errorf("Wide(%s) = %v, want %s", in, got, want)
		}
	}
	for _, in := range []string{"::ffff:198.18.7.1", "2001:db8::1"} {
		if got := Wide(netip.MustParseAddr(in)); got.IsValid() {
			t.Errorf("Wide(%s) = %v, want none", in, got)
		}
	}
}
