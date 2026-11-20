package token

import (
	"net/netip"
	"testing"
	"time"
)

var (
	t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	a  = netip.MustParseAddrPort("203.0.113.7:4000")
)

func TestCheck(t *testing.T) {
	s := New(t0)
	tok := s.Make(a, t0)
	if !s.Check(a, tok, t0) {
		t.Fatal("fresh token rejected")
	}
	for _, other := range []string{"203.0.113.7:4001", "203.0.113.8:4000", "[2001:db8::7]:4000"} {
		if s.Check(netip.MustParseAddrPort(other), tok, t0) {
			t.Errorf("token for %s accepted from %s", a, other)
		}
	}
	bad := tok
	bad[31] ^= 1
	if s.Check(a, bad, t0) {
		t.Error("modified token accepted")
	}
	if s.Check(a, [Size]byte{}, t0) {
		t.Error("zero token accepted")
	}
}

// TestIPv4Only checks that kolo-dht is IPv4 only: no IPv6 address, IPv4-mapped included, passes a check.
func TestIPv4Only(t *testing.T) {
	s := New(t0)
	if s.Check(netip.MustParseAddrPort("[::ffff:203.0.113.7]:4000"), s.Make(a, t0), t0) {
		t.Error("v4-mapped form of the address accepted")
	}
	for _, v6 := range []string{"[::ffff:203.0.113.7]:4000", "[2001:db8::7]:4000", "[fe80::1%eth0]:4000"} {
		ap := netip.MustParseAddrPort(v6)
		if s.Check(ap, s.Make(ap, t0), t0) {
			t.Errorf("token for %s accepted", v6)
		}
	}
}

func TestRotation(t *testing.T) {
	s := New(t0)
	tok := s.Make(a, t0)
	for _, tt := range []struct {
		after time.Duration
		ok    bool
	}{
		{Rotation - time.Second, true},
		{Rotation, true},
		{2*Rotation - time.Second, true},
		{2 * Rotation, false},
	} {
		s := New(t0)
		tok := s.Make(a, t0)
		if got := s.Check(a, tok, t0.Add(tt.after)); got != tt.ok {
			t.Errorf("token checked after %v: %v, want %v", tt.after, got, tt.ok)
		}
	}
	// A long gap replaces both secrets at once.
	if s.Check(a, tok, t0.Add(10*Rotation)) {
		t.Error("token accepted after a long gap")
	}
	fresh := s.Make(a, t0.Add(10*Rotation))
	if !s.Check(a, fresh, t0.Add(10*Rotation)) {
		t.Error("fresh token rejected after a long gap")
	}
	if fresh == tok {
		t.Error("secret did not change")
	}
}

func TestLifetimeBoundedByEpochs(t *testing.T) {
	s := New(t0)
	tok := s.Make(a, t0)
	other := netip.MustParseAddrPort("198.51.100.1:1")
	s.Make(other, t0.Add(2*Rotation-time.Second))
	if !s.Check(a, tok, t0.Add(2*Rotation-time.Millisecond)) {
		t.Error("token rejected before twice Rotation")
	}
	if s.Check(a, tok, t0.Add(2*Rotation)) {
		t.Error("token accepted at twice Rotation after a late rotation")
	}
}

func TestSecretsDiffer(t *testing.T) {
	if x, y := New(t0).Make(a, t0), New(t0).Make(a, t0); x == y {
		t.Error("two instances made the same token")
	}
}

func TestClockBackwards(t *testing.T) {
	s := New(t0)
	tok := s.Make(a, t0)
	if !s.Check(a, tok, t0.Add(-time.Hour)) {
		t.Error("token rejected when the clock went back")
	}
}

// TestLifetimeCoversMeasuredGap checks that a token outlives the longest measured gap before its use (31s), with margin.
func TestLifetimeCoversMeasuredGap(t *testing.T) {
	for off := time.Duration(0); off < 40*time.Second; off += 5 * time.Second {
		s := New(t0)
		made := t0.Add(off)
		tok := s.Make(a, made)
		for _, after := range []time.Duration{31 * time.Second, 40*time.Second - time.Millisecond} {
			if !s.Check(a, tok, made.Add(after)) {
				t.Errorf("token made %v into the epoch rejected %v later", off, after)
			}
		}
		if s.Check(a, tok, made.Add(80*time.Second)) {
			t.Errorf("token made %v into the epoch accepted 80s later", off)
		}
	}
}
