package kolodht

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/ciranda-dev/kolo-dht/internal/wire"
)

var natT0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// server returns a server address in the i-th /24 of 203.0.0.0/16.
func server(i int) netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{203, 0, byte(i), 1}), 4000)
}

// window returns a natState holding one sample per address, from servers in distinct /24s, all at natT0.
func window(obs ...netip.AddrPort) *natState {
	s := newNAT(time.Hour)
	for i, o := range obs {
		s.add(server(i), o, natT0)
	}
	return s
}

func TestNATClass(t *testing.T) {
	a := netip.MustParseAddrPort("192.0.2.9:4000")
	n := newNAT(time.Hour)
	if n.class(natT0) != wire.ClassUnknown {
		t.Fatal("no samples: not unknown")
	}
	n.add(server(1), a, natT0)
	n.add(server(1), netip.MustParseAddrPort("192.0.2.9:4001"), natT0)
	if len(n.samples) != 1 {
		t.Fatal("a second sample from the same server counted as another server")
	}
	n.add(server(1), a, natT0)
	n.add(server(2), a, natT0)
	if n.class(natT0) != wire.ClassUnknown {
		t.Fatal("two agreeing samples: not unknown, want at least 3")
	}
	n.add(server(3), a, natT0)
	if n.class(natT0) != wire.ClassConsistent {
		t.Fatalf("same mapping from 3 servers: %v", n.class(natT0))
	}
	n.add(server(3), netip.MustParseAddrPort("192.0.2.9:5000"), natT0)
	if n.class(natT0) != wire.ClassConsistent {
		t.Fatalf("2 of 3 agree: %v", n.class(natT0))
	}
	if ip, ok := n.publicIP(); !ok || ip != a.Addr() {
		t.Fatalf("publicIP = %v %v", ip, ok)
	}
}

// TestNATMajority checks the share rule: random only when the most common address is not reported by more than half
// of the samples, and never below 3 samples.
func TestNATMajority(t *testing.T) {
	a := netip.MustParseAddrPort("192.0.2.9:4000")
	p := func(port uint16) netip.AddrPort { return netip.AddrPortFrom(a.Addr(), port) }
	tests := []struct {
		name string
		obs  []netip.AddrPort
		want wire.Class
	}{
		{"two different", []netip.AddrPort{a, p(1)}, wire.ClassUnknown},
		{"3 of 3", []netip.AddrPort{a, a, a}, wire.ClassConsistent},
		{"2 of 3", []netip.AddrPort{a, a, p(1)}, wire.ClassConsistent},
		{"3 different", []netip.AddrPort{a, p(1), p(2)}, wire.ClassRandom},
		{"2 of 4", []netip.AddrPort{a, a, p(1), p(2)}, wire.ClassRandom},
		{"2 and 2", []netip.AddrPort{a, a, p(1), p(1)}, wire.ClassRandom},
		{"3 of 4", []netip.AddrPort{a, a, a, p(1)}, wire.ClassConsistent},
		{"3 of 5", []netip.AddrPort{a, a, a, p(1), p(2)}, wire.ClassConsistent},
		{"4 of 8", []netip.AddrPort{a, a, a, a, p(1), p(2), p(3), p(4)}, wire.ClassRandom},
		{"5 of 8", []netip.AddrPort{a, a, a, a, a, p(1), p(2), p(3)}, wire.ClassConsistent},
		{"8 different", []netip.AddrPort{a, p(1), p(2), p(3), p(4), p(5), p(6), p(7)}, wire.ClassRandom},
	}
	for _, tt := range tests {
		if got := window(tt.obs...).class(natT0); got != tt.want {
			t.Errorf("%s: class %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestNATBounded(t *testing.T) {
	n := newNAT(time.Hour)
	for i := range 100 {
		n.add(server(i), netip.MustParseAddrPort(fmt.Sprintf("192.0.2.%d:4000", i%3)), natT0)
	}
	if len(n.samples) != maxSamples {
		t.Fatalf("%d samples kept", len(n.samples))
	}
	// The newest samples win: the last 8 alternate between three IPs, so the most common one is reported.
	if _, ok := n.publicIP(); !ok {
		t.Fatal("no public IP")
	}
}

// TestNATAge drops samples older than the age, so a window of old samples falls back to unknown.
func TestNATAge(t *testing.T) {
	a := netip.MustParseAddrPort("192.0.2.9:4000")
	n := newNAT(time.Minute)
	for i := range 3 {
		n.add(server(i), a, natT0.Add(time.Duration(i)*10*time.Second))
	}
	if c := n.class(natT0.Add(time.Minute - time.Nanosecond)); c != wire.ClassConsistent {
		t.Fatalf("fresh samples: %v", c)
	}
	if c := n.class(natT0.Add(time.Minute)); c != wire.ClassUnknown || len(n.samples) != 2 {
		t.Fatalf("one sample aged out: %v with %d samples", c, len(n.samples))
	}
	n.add(server(5), a, natT0.Add(80*time.Second))
	if len(n.samples) != 1 {
		t.Fatalf("%d samples after the others aged out", len(n.samples))
	}
	if !n.trusted(a, natT0.Add(80*time.Second)) || n.trusted(netip.MustParseAddrPort("192.0.2.9:1"), natT0.Add(80*time.Second)) {
		t.Fatal("trusted does not follow the live sample")
	}
}

// TestNATNewMajority clears the samples that disagree with a new majority, the sign of a network change.
func TestNATNewMajority(t *testing.T) {
	a := netip.MustParseAddrPort("192.0.2.9:4000")
	x := netip.MustParseAddrPort("198.51.100.4:6000")
	n := window(a, a, a, a, a, a, a, a)
	for i := range 4 {
		n.add(server(i), x, natT0)
	}
	if c := n.class(natT0); c != wire.ClassRandom || len(n.samples) != 8 {
		t.Fatalf("4 old and 4 new: %v with %d samples", c, len(n.samples))
	}
	n.add(server(4), x, natT0)
	if c := n.class(natT0); c != wire.ClassConsistent || len(n.samples) != 5 {
		t.Fatalf("new majority: %v with %d samples, want the 3 old ones cleared", c, len(n.samples))
	}
	if !n.trusted(x, natT0) || n.trusted(a, natT0) {
		t.Fatal("trusted does not follow the new majority")
	}
	// The first majority clears nothing: a liar seen before it stays and counts.
	l := netip.MustParseAddrPort("192.0.2.66:1")
	m := window(l, a, a)
	if c := m.class(natT0); c != wire.ClassConsistent || len(m.samples) != 3 {
		t.Fatalf("first majority: %v with %d samples", c, len(m.samples))
	}
}

// TestNATLoopbackPerServer counts a loopback server by its address and port: it runs on this host, behind no NAT,
// so servers on 127.0.0.1 alone can classify a node.
func TestNATLoopbackPerServer(t *testing.T) {
	me := netip.MustParseAddrPort("127.0.0.1:5000")
	n := newNAT(time.Hour)
	for port := range uint16(3) {
		n.add(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 4000+port), me, natT0)
	}
	if c := n.class(natT0); c != wire.ClassConsistent || len(n.samples) != 3 {
		t.Fatalf("3 loopback servers: %v with %d samples", c, len(n.samples))
	}
	// Two private servers in one /24 still count once.
	p := newNAT(time.Hour)
	p.add(netip.MustParseAddrPort("192.168.1.2:4000"), me, natT0)
	p.add(netip.MustParseAddrPort("192.168.1.3:4000"), me, natT0)
	if len(p.samples) != 1 {
		t.Fatalf("%d samples from one private /24", len(p.samples))
	}
}

func TestTrustedFewSamples(t *testing.T) {
	me := netip.MustParseAddrPort("192.0.2.9:4000")
	other := netip.MustParseAddrPort("198.51.100.77:9")
	n := newNAT(time.Hour)
	if !n.trusted(other, natT0) {
		t.Fatal("no samples: nothing to compare, any address is taken")
	}
	n.add(server(1), me, natT0)
	if !n.trusted(me, natT0) {
		t.Fatal("one sample: its own address refused")
	}
	if n.trusted(other, natT0) {
		t.Fatal("one sample: an address no server reported was trusted")
	}
	n.add(server(2), me, natT0)
	if !n.trusted(me, natT0) || n.trusted(other, natT0) {
		t.Fatal("two agreeing samples: trusted is not their address")
	}
	// Two disagreeing samples cannot tell the liar: each reported address may be signed, nothing else.
	lie := netip.MustParseAddrPort("198.51.100.66:1")
	n.add(server(2), lie, natT0)
	if !n.trusted(me, natT0) || !n.trusted(lie, natT0) || n.trusted(other, natT0) {
		t.Fatal("two disagreeing samples: trusted is not one of them")
	}
	// From three samples on, only the majority.
	n.add(server(3), me, natT0)
	if !n.trusted(me, natT0) || n.trusted(lie, natT0) {
		t.Fatal("three samples: trusted is not the majority")
	}
	// A random mapping: an address with the IP more than half of the samples report; a tie trusts nothing.
	r := window(me, netip.AddrPortFrom(me.Addr(), 1), netip.AddrPortFrom(me.Addr(), 2), lie)
	if !r.trusted(netip.AddrPortFrom(me.Addr(), 3), natT0) || r.trusted(lie, natT0) {
		t.Fatal("random mapping: trusted does not follow the IP majority")
	}
	tie := window(me, netip.AddrPortFrom(me.Addr(), 1), lie, netip.AddrPortFrom(lie.Addr(), 2))
	if tie.trusted(me, natT0) || tie.trusted(lie, natT0) {
		t.Fatal("IP tie: an address was trusted")
	}
}

// TestTrustedExpires: trusted drops expired samples first, so an old majority does not decide.
func TestTrustedExpires(t *testing.T) {
	a, b := netip.MustParseAddrPort("192.0.2.9:4000"), netip.MustParseAddrPort("192.0.2.10:4000")
	if !window(a, a, a).trusted(b, natT0.Add(time.Hour)) {
		t.Fatal("expired samples refused an address")
	}
}
