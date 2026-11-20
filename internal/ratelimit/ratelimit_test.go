package ratelimit

import (
	"net/netip"
	"testing"
	"time"
)

var t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func ip(s string) netip.Addr { return netip.MustParseAddr(s) }

func allowN(l *Limiter, a netip.Addr, n int, now time.Time) int {
	ok := 0
	for range n {
		if l.Allow(a, now) {
			ok++
		}
	}
	return ok
}

func TestPerHost(t *testing.T) {
	l := New(3, 100, 1000, t0)
	if got := allowN(l, ip("203.0.113.1"), 10, t0); got != 3 {
		t.Fatalf("host allowed %d, want 3", got)
	}
	if got := allowN(l, ip("203.0.113.2"), 10, t0); got != 3 {
		t.Fatalf("second host allowed %d, want 3", got)
	}
}

func TestPerGroup(t *testing.T) {
	l := New(3, 5, 1000, t0)
	got := 0
	for i := range 10 {
		got += allowN(l, netip.AddrFrom4([4]byte{203, 0, 113, byte(i)}), 3, t0)
	}
	if got != 5 {
		t.Fatalf("one /24 allowed %d, want 5", got)
	}
	if !l.Allow(ip("198.51.100.1"), t0) {
		t.Fatal("other /24 refused")
	}
}

func TestTotal(t *testing.T) {
	l := New(10, 10, 25, t0)
	got := 0
	for i := range 50 {
		got += allowN(l, netip.AddrFrom4([4]byte{10, byte(i), 0, 1}), 1, t0)
	}
	if got != 25 {
		t.Fatalf("allowed %d in total, want 25", got)
	}
}

func TestWindow(t *testing.T) {
	l := New(2, 100, 1000, t0)
	a := ip("203.0.113.1")
	allowN(l, a, 5, t0)
	if l.Allow(a, t0.Add(Window-time.Millisecond)) {
		t.Fatal("allowed within the same window")
	}
	if got := allowN(l, a, 5, t0.Add(Window)); got != 2 {
		t.Fatalf("next window allowed %d, want 2", got)
	}
	if got := allowN(l, a, 5, t0.Add(10*Window+time.Millisecond)); got != 2 {
		t.Fatalf("later window allowed %d, want 2", got)
	}
}

func TestRefusedNotCounted(t *testing.T) {
	l := New(1, 2, 1000, t0)
	a := ip("203.0.113.1")
	allowN(l, a, 100, t0)
	// a's refused packets must not use up the /24.
	if !l.Allow(ip("203.0.113.2"), t0) {
		t.Fatal("refused packets were counted against the group")
	}
}

func TestBounded(t *testing.T) {
	l := New(1, 1, 50, t0)
	for i := range 10000 {
		l.Allow(netip.AddrFrom4([4]byte{byte(i >> 8), byte(i), 1, 1}), t0)
	}
	if n := l.entries(); n > 100 {
		t.Fatalf("limiter holds %d entries, want at most 100 (2 x total)", n)
	}
}
