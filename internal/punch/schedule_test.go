package punch

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func TestRandomPort(t *testing.T) {
	lo, hi := uint16(65535), uint16(0)
	for range 200_000 {
		p := RandomPort()
		if p < MinRandomPort {
			t.Fatalf("port %d below %d", p, MinRandomPort)
		}
		lo, hi = min(lo, p), max(hi, p)
	}
	if lo > MinRandomPort+5 || hi < 65530 {
		t.Fatalf("ports span %d..%d, want about 1000..65535", lo, hi)
	}
}

func TestRunTries(t *testing.T) {
	checkGoroutines(t)
	var at []time.Duration
	start := time.Now()
	Run(context.Background(), nil, 0, 5*time.Millisecond, 4, func(i int) {
		if i != len(at) {
			t.Fatalf("tick %d after %d ticks", i, len(at))
		}
		at = append(at, time.Since(start))
	})
	if len(at) != 4 {
		t.Fatalf("%d ticks, want 4", len(at))
	}
	if at[0] > 3*time.Millisecond || at[3] < 15*time.Millisecond {
		t.Fatalf("ticks at %v: want the first at once, then every 5ms", at)
	}
}

func TestRunDelay(t *testing.T) {
	var first time.Duration
	start := time.Now()
	Run(context.Background(), nil, 30*time.Millisecond, time.Millisecond, 1, func(int) { first = time.Since(start) })
	if first < 30*time.Millisecond {
		t.Fatalf("first tick after %v, want at least the 30ms delay", first)
	}
}

func TestRunStops(t *testing.T) {
	checkGoroutines(t)
	stop := make(chan struct{})
	n := 0
	Run(context.Background(), stop, 0, time.Millisecond, 1000, func(i int) {
		if n++; n == 3 {
			close(stop)
		}
	})
	if n != 3 {
		t.Fatalf("%d ticks after stop at 3", n)
	}
	ctx, cancel := context.WithCancel(context.Background())
	n = 0
	Run(ctx, nil, 0, time.Millisecond, 1000, func(i int) {
		if n++; n == 2 {
			cancel()
		}
	})
	if n != 2 {
		t.Fatalf("%d ticks after cancel at 2", n)
	}
	n = 0
	Run(ctx, nil, 0, time.Millisecond, 10, func(int) { n++ })
	if n != 0 {
		t.Fatalf("%d ticks with a done context", n)
	}
}

// TestRandomProbes sends every probe to the verified IP, on ports from 1000, as many as the tries.
func TestRandomProbes(t *testing.T) {
	ip := netip.MustParseAddr("198.19.4.4")
	var got []netip.AddrPort
	RandomProbes(context.Background(), nil, ip, time.Microsecond, 300, RandomPort, func(ap netip.AddrPort) {
		got = append(got, ap)
	})
	if len(got) != 300 {
		t.Fatalf("%d probes, want 300", len(got))
	}
	ports := map[uint16]bool{}
	for _, ap := range got {
		if ap.Addr() != ip || ap.Port() < MinRandomPort {
			t.Fatalf("probe to %v", ap)
		}
		ports[ap.Port()] = true
	}
	if len(ports) < 290 {
		t.Fatalf("only %d distinct ports in 300 probes", len(ports))
	}
}

// TestBirthday waits the delay, then cycles holders one per tick, low TTL for the first pass only.
func TestBirthday(t *testing.T) {
	type send struct{ i, ttl int }
	var got []send
	start := time.Now()
	var first time.Duration
	Birthday(context.Background(), nil, 20*time.Millisecond, time.Microsecond, 10, 4, 5, func(i, ttl int) {
		if len(got) == 0 {
			first = time.Since(start)
		}
		got = append(got, send{i, ttl})
	})
	want := []send{{0, 5}, {1, 5}, {2, 5}, {3, 5}, {0, 64}, {1, 64}, {2, 64}, {3, 64}, {0, 64}, {1, 64}}
	if len(got) != len(want) {
		t.Fatalf("sends %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("sends %v, want %v", got, want)
		}
	}
	if first < 20*time.Millisecond {
		t.Fatalf("first send after %v, want the 20ms delay first", first)
	}
}

// TestRandomProbesIPv4Only sends nothing toward an IP that is not IPv4, IPv4-mapped included.
func TestRandomProbesIPv4Only(t *testing.T) {
	for _, s := range []string{"::ffff:198.19.4.4", "2001:db8::1"} {
		n := 0
		RandomProbes(context.Background(), nil, netip.MustParseAddr(s), time.Microsecond, 10, RandomPort, func(netip.AddrPort) { n++ })
		if n != 0 {
			t.Errorf("%d probes toward %s", n, s)
		}
	}
}
