package kolodht

import (
	"net/netip"
	"slices"
	"testing"
	"time"
)

// TestRecordAddrs lists Addr and the relays' stored addresses once each, IPv4 only.
func TestRecordAddrs(t *testing.T) {
	a := netip.MustParseAddrPort("203.0.113.7:4000")
	b := netip.MustParseAddrPort("203.0.113.7:4001")
	c := netip.MustParseAddrPort("198.51.100.9:5000")
	r := Record{Addr: a, relays: []relay{
		{addr: a}, {addr: b}, {addr: c}, {addr: b},
		{addr: netip.MustParseAddrPort("[2001:db8::1]:4000")}, {addr: netip.MustParseAddrPort("[::ffff:203.0.113.8]:4000")}, {},
	}}
	if got := r.Addrs(); !slices.Equal(got, []netip.AddrPort{a, b, c}) {
		t.Fatalf("Addrs = %v, want %v", got, []netip.AddrPort{a, b, c})
	}
	if got := (Record{}).Addrs(); len(got) != 0 {
		t.Fatalf("Addrs of an empty record = %v", got)
	}
}

func TestDefaultRandomPunchInterval(t *testing.T) {
	c, err := (&Config{}).withDefaults()
	if err != nil {
		t.Fatal(err)
	}
	if DefaultRandomPunchInterval != 20*time.Second || c.RandomPunchInterval != DefaultRandomPunchInterval {
		t.Fatalf("DefaultRandomPunchInterval %v, default %v", DefaultRandomPunchInterval, c.RandomPunchInterval)
	}
}
