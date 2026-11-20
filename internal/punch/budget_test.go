package punch

import (
	"net/netip"
	"sync"
	"testing"
	"time"
)

var (
	hostA = netip.MustParseAddr("198.19.1.1")
	hostB = netip.MustParseAddr("198.19.2.1")
	hostC = netip.MustParseAddr("198.19.3.1")
	t0    = time.Unix(1_000_000, 0)
)

func limits() Limits {
	return Limits{Punches: 2, PerTarget: 1, PerRequester: 1, Sockets: 300, Interval: 20 * time.Second}
}

func TestBudgetPunchCap(t *testing.T) {
	b := NewBudget(limits())
	g1, ok := b.Acquire(Connector, hostA, 0, t0)
	if !ok {
		t.Fatal("first punch refused")
	}
	if _, ok := b.Acquire(Announcer, hostB, 0, t0); !ok {
		t.Fatal("second punch refused under a cap of 2")
	}
	if _, ok := b.Acquire(Connector, hostC, 0, t0); ok {
		t.Fatal("third punch granted under a cap of 2")
	}
	g1.Done(t0)
	if b.Active() != 1 {
		t.Fatalf("Active = %d after one Done, want 1", b.Active())
	}
}

func TestBudgetPerHost(t *testing.T) {
	b := NewBudget(Limits{Punches: 4, PerTarget: 1, PerRequester: 2, Sockets: 300})
	if _, ok := b.Acquire(Connector, hostA, 0, t0); !ok {
		t.Fatal("first punch to a target refused")
	}
	if _, ok := b.Acquire(Connector, hostA, 0, t0); ok {
		t.Fatal("second punch to one target granted under PerTarget 1")
	}
	if _, ok := b.Acquire(Announcer, hostA, 0, t0); !ok {
		t.Fatal("announcer punch for a host the connector targets refused")
	}
	if _, ok := b.Acquire(Announcer, hostA, 0, t0); !ok {
		t.Fatal("second requester punch refused under PerRequester 2")
	}
	if _, ok := b.Acquire(Announcer, hostA, 0, t0); ok {
		t.Fatal("third requester punch granted under PerRequester 2")
	}
}

func TestBudgetInterval(t *testing.T) {
	b := NewBudget(limits())
	g, _ := b.Acquire(Connector, hostA, 0, t0)
	end := t0.Add(5 * time.Second)
	g.Done(end)
	if _, ok := b.Acquire(Connector, hostB, 0, end.Add(19*time.Second)); ok {
		t.Fatal("random punch granted 19s after the last one ended, interval 20s")
	}
	if _, ok := b.Acquire(Connector, hostB, 0, end.Add(20*time.Second)); !ok {
		t.Fatal("random punch refused 20s after the last one ended")
	}
}

// A grant ended with a zero time, such as a relay that failed before any punch ran, does not start the interval.
func TestBudgetDoneWithoutPunch(t *testing.T) {
	b := NewBudget(limits())
	g, _ := b.Acquire(Connector, hostA, 0, t0)
	g.Done(time.Time{})
	g2, ok := b.Acquire(Connector, hostA, 0, t0)
	if !ok {
		t.Fatal("interval started by a grant that never punched")
	}
	// Nor does it end an interval that a real punch started.
	g3, _ := b.Acquire(Connector, hostB, 0, t0)
	g2.Done(t0)
	g3.Done(time.Time{})
	if _, ok := b.Acquire(Connector, hostC, 0, t0.Add(time.Second)); ok {
		t.Fatal("a zero Done cleared the interval")
	}
}

func TestBudgetSockets(t *testing.T) {
	b := NewBudget(Limits{Punches: 4, PerTarget: 4, PerRequester: 4, Sockets: 300})
	g, ok := b.Acquire(Connector, hostA, 255, t0)
	if !ok {
		t.Fatal("255 sockets refused under 300")
	}
	// All or nothing: a refused grant takes no slot and no socket.
	if _, ok := b.Acquire(Connector, hostB, 255, t0); ok {
		t.Fatal("510 sockets granted under 300")
	}
	if b.Active() != 1 || b.Sockets() != 255 {
		t.Fatalf("after a refusal: Active %d, Sockets %d, want 1 and 255", b.Active(), b.Sockets())
	}
	if _, ok := b.Acquire(Connector, hostB, 45, t0); !ok {
		t.Fatal("45 sockets refused with 45 left")
	}
	// Sockets come back one by one, never more than the grant holds, and outlive Done.
	g.Done(t0)
	g.ReleaseSockets(254)
	g.ReleaseSockets(5)
	if b.Sockets() != 45 {
		t.Fatalf("Sockets = %d, want 45", b.Sockets())
	}
}

func TestBudgetDoneIdempotent(t *testing.T) {
	b := NewBudget(Limits{Punches: 2, PerTarget: 2, PerRequester: 2, Sockets: 10})
	g, _ := b.Acquire(Connector, hostA, 0, t0)
	b.Acquire(Connector, hostA, 0, t0)
	g.Done(t0)
	g.Done(t0)
	if b.Active() != 1 {
		t.Fatalf("Active = %d after a double Done, want 1", b.Active())
	}
}

func TestBudgetConcurrent(t *testing.T) {
	b := NewBudget(Limits{Punches: 3, PerTarget: 3, PerRequester: 3, Sockets: 1000})
	var wg sync.WaitGroup
	var mu sync.Mutex
	most := 0
	for i := range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h := netip.AddrFrom4([4]byte{198, 19, byte(i % 4), 1})
			if g, ok := b.Acquire(Connector, h, 10, t0); ok {
				mu.Lock()
				most = max(most, b.Active())
				mu.Unlock()
				g.ReleaseSockets(10)
				g.Done(t0)
			}
		}()
	}
	wg.Wait()
	if most > 3 || b.Active() != 0 || b.Sockets() != 0 {
		t.Fatalf("most %d at once, then Active %d, Sockets %d", most, b.Active(), b.Sockets())
	}
}

// TestBudgetIPv4Only refuses a host that is not IPv4, so an IPv4-mapped form cannot get a count of its own.
func TestBudgetIPv4Only(t *testing.T) {
	for _, h := range []netip.Addr{netip.AddrFrom16(hostA.As16()), netip.MustParseAddr("2001:db8::1"), {}} {
		if _, ok := NewBudget(limits()).Acquire(Connector, h, 0, t0); ok {
			t.Errorf("Acquire for %v granted", h)
		}
	}
}

func burstLimits() Limits {
	return Limits{Punches: 4, PerTarget: 4, PerRequester: 4, Sockets: 300, Interval: time.Second, Cooldown: time.Minute, PerMinute: 3}
}

// TestBurstCooldown: a burst toward a host, or with another key such as the storer that asked, holds its keys while
// it runs and for Cooldown from its end, once it connected.
func TestBurstCooldown(t *testing.T) {
	b := NewBudget(burstLimits())
	g, ok := b.Burst(Announcer, hostA, 0, t0, hostC)
	if !ok {
		t.Fatal("first burst refused")
	}
	for _, try := range []struct {
		host, also netip.Addr
	}{{hostA, hostB}, {hostB, hostC}} {
		if _, ok := b.Burst(Announcer, try.host, 0, t0.Add(time.Second), try.also); ok {
			t.Fatalf("burst %v, %v inside the cooldown", try.host, try.also)
		}
	}
	end := t0.Add(50 * time.Second)
	g.Connected()
	g.Done(end)
	if _, ok := b.Burst(Announcer, hostA, 0, t0.Add(70*time.Second), netip.Addr{}); ok {
		t.Fatal("burst a minute after the start but inside a minute of the end")
	}
	if _, ok := b.Burst(Announcer, hostB, 0, t0.Add(70*time.Second), netip.Addr{}); !ok {
		t.Fatal("another host refused")
	}
	if _, ok := b.Burst(Announcer, hostA, 0, end.Add(time.Minute), netip.Addr{}); !ok {
		t.Fatal("burst a minute after the end refused")
	}
	// The roles count apart, and Acquire knows no cooldown.
	if _, ok := b.Burst(Connector, hostB, 0, end.Add(time.Minute), netip.Addr{}); !ok {
		t.Fatal("connector burst refused by an announcer cooldown")
	}
	if _, ok := b.Acquire(Announcer, hostB, 0, end.Add(time.Minute)); !ok {
		t.Fatal("Acquire refused by a cooldown")
	}
}

// TestBurstPerMinute: at most PerMinute bursts start in any minute, both roles, whatever their hosts.
func TestBurstPerMinute(t *testing.T) {
	b := NewBudget(burstLimits())
	for i, h := range []netip.Addr{hostA, hostB, hostC} {
		g, ok := b.Burst(Role(i%2), h, 0, t0.Add(time.Duration(i)*2*time.Second), netip.Addr{})
		if !ok {
			t.Fatalf("burst %d refused", i)
		}
		g.Done(time.Time{})
	}
	d := netip.MustParseAddr("198.19.4.1")
	if _, ok := b.Burst(Connector, d, 0, t0.Add(59*time.Second), netip.Addr{}); ok {
		t.Fatal("fourth burst in a minute granted")
	}
	if _, ok := b.Acquire(Connector, d, 0, t0.Add(59*time.Second)); !ok {
		t.Fatal("Acquire refused by the per-minute cap")
	}
	if _, ok := b.Burst(Connector, d, 0, t0.Add(61*time.Second), netip.Addr{}); !ok {
		t.Fatal("burst refused after the oldest left the minute")
	}
}

// TestBurstRefusedLeavesNoTrace: a burst over another limit starts no cooldown and counts in no minute.
func TestBurstRefusedLeavesNoTrace(t *testing.T) {
	l := burstLimits()
	l.Punches = 1
	b := NewBudget(l)
	g, _ := b.Burst(Connector, hostA, 0, t0, netip.Addr{})
	for range 5 {
		if _, ok := b.Burst(Connector, hostB, 0, t0, netip.Addr{}); ok {
			t.Fatal("burst over the punch cap")
		}
	}
	g.Done(time.Time{})
	if _, ok := b.Burst(Connector, hostB, 0, t0.Add(2*time.Second), netip.Addr{}); !ok {
		t.Fatal("refused bursts left a cooldown or used the minute")
	}
}

// TestBurstZeroDone: a burst ended with a zero time keeps the cooldown of its start and does not grow it.
func TestBurstZeroDone(t *testing.T) {
	b := NewBudget(burstLimits())
	g, _ := b.Burst(Connector, hostA, 0, t0, netip.Addr{})
	g.Done(time.Time{})
	if _, ok := b.Burst(Connector, hostA, 0, t0.Add(30*time.Second), netip.Addr{}); ok {
		t.Fatal("a zero Done cleared the cooldown")
	}
	if _, ok := b.Burst(Connector, hostA, 0, t0.Add(time.Minute), netip.Addr{}); !ok {
		t.Fatal("a zero Done grew the cooldown")
	}
}

// TestBurstBackoff: a host's cooldown doubles after each burst without a connection, up to 1<<MaxBackoff times,
// and is back to Cooldown after one that connected, whether Connected comes before or after Done.
func TestBurstBackoff(t *testing.T) {
	for _, role := range []Role{Connector, Announcer} {
		b := NewBudget(burstLimits())
		now := t0
		burst := func(wait time.Duration, connected, after bool) {
			t.Helper()
			if wait > 0 {
				if _, ok := b.Burst(role, hostA, 0, now.Add(wait-time.Second), netip.Addr{}); ok {
					t.Fatalf("role %d: burst %v before its cooldown of %v", role, wait-time.Second, wait)
				}
			}
			now = now.Add(wait)
			g, ok := b.Burst(role, hostA, 0, now, netip.Addr{})
			if !ok {
				t.Fatalf("role %d: burst refused after its cooldown of %v", role, wait)
			}
			if connected && !after {
				g.Connected()
			}
			now = now.Add(5 * time.Second)
			g.Done(now)
			if connected && after {
				g.Connected()
			}
		}
		burst(0, false, false)
		for i := 1; i <= MaxBackoff+2; i++ {
			burst(time.Minute<<min(i, MaxBackoff), false, false)
		}
		burst(time.Minute<<MaxBackoff, true, true)
		burst(time.Minute, true, false)
		burst(time.Minute, false, false)
		burst(2*time.Minute, false, false)
	}
}

// TestBurstStorerNoBackoff: a storer's cooldown stays Cooldown, whatever its bursts made.
func TestBurstStorerNoBackoff(t *testing.T) {
	b := NewBudget(burstLimits())
	now := t0
	for i := range 3 {
		g, ok := b.Burst(Announcer, netip.AddrFrom4([4]byte{198, 19, byte(10 + i), 1}), 0, now, hostC)
		if !ok {
			t.Fatalf("burst %d through one storer refused after Cooldown", i)
		}
		g.Done(now.Add(time.Second))
		now = now.Add(time.Second + time.Minute)
	}
}

// TestBurstRequesterNetwork: at the announcer, a requester's /24 cools down with its IP; the connector keys only the IP.
func TestBurstRequesterNetwork(t *testing.T) {
	near := netip.MustParseAddr("198.19.1.200")
	b := NewBudget(burstLimits())
	g, _ := b.Burst(Announcer, hostA, 0, t0, netip.Addr{})
	g.Done(t0.Add(time.Second))
	if _, ok := b.Burst(Announcer, near, 0, t0.Add(30*time.Second), netip.Addr{}); ok {
		t.Fatal("a requester in the same /24 granted inside the cooldown")
	}
	if _, ok := b.Burst(Announcer, hostB, 0, t0.Add(30*time.Second), netip.Addr{}); !ok {
		t.Fatal("a requester in another /24 refused")
	}
	later := t0.Add(time.Hour)
	g, _ = b.Burst(Connector, hostA, 0, later, netip.Addr{})
	g.Done(later.Add(time.Second))
	if _, ok := b.Burst(Connector, near, 0, later.Add(30*time.Second), netip.Addr{}); !ok {
		t.Fatal("the connector refused another IP of the same /24")
	}
}

// TestBurstKeyKinds: a storer's cooldown and a requester's never meet, though they share an IP.
func TestBurstKeyKinds(t *testing.T) {
	b := NewBudget(burstLimits())
	g, _ := b.Burst(Announcer, hostA, 0, t0, hostB)
	g.Done(t0.Add(time.Second))
	if _, ok := b.Burst(Announcer, hostB, 0, t0.Add(3*time.Second), hostC); !ok {
		t.Fatal("a requester at a cooling storer's IP refused")
	}
	b = NewBudget(burstLimits())
	g, _ = b.Burst(Announcer, netip.MustParseAddr("198.19.9.1"), 0, t0.Add(3*time.Second), netip.Addr{})
	g.Done(t0.Add(4 * time.Second))
	if _, ok := b.Burst(Announcer, netip.MustParseAddr("198.19.20.1"), 0, t0.Add(6*time.Second), netip.MustParseAddr("198.19.9.0")); !ok {
		t.Fatal("a storer at the base address of a cooling /24 refused")
	}
}

// TestBurstSlotMonopoly: requester IPs that never connect and take the one random slot again as soon as it is free,
// alternating over two storers, still leave an honest requester grants over an hour, in one /24 or in two.
func TestBurstSlotMonopoly(t *testing.T) {
	for _, c := range []struct {
		name string
		att  []netip.Addr
	}{
		{"one /24", []netip.Addr{netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("203.0.113.2")}},
		{"two /24s", []netip.Addr{netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("203.0.114.1")}},
	} {
		t.Run(c.name, func(t *testing.T) {
			b := NewBudget(Limits{Punches: 1, PerTarget: 1, PerRequester: 1, Sockets: 256, Interval: 20 * time.Second, Cooldown: time.Minute, PerMinute: 4})
			st := []netip.Addr{netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("198.51.100.2")}
			honest, hs := netip.MustParseAddr("192.0.2.9"), netip.MustParseAddr("198.51.100.3")
			var g *Grant
			var end time.Time
			attacks, honestOK := 0, 0
			for ms := 0; ms < 3600_000; ms += 100 {
				now := t0.Add(time.Duration(ms) * time.Millisecond)
				if g != nil && !now.Before(end) {
					g.Done(now) // the slot is back when the probes end, 35s in
					g = nil
				}
				for i := range c.att {
					for j := range st {
						if x, ok := b.Burst(Announcer, c.att[i], 0, now, st[j]); g == nil && ok {
							g, end = x, now.Add(35*time.Second)
							attacks++
						}
					}
				}
				if ms%1000 == 0 {
					if x, ok := b.Burst(Announcer, honest, 0, now, hs); ok {
						honestOK++
						x.Connected()
						x.Done(now.Add(5 * time.Second))
					}
				}
			}
			t.Logf("in 1h: attacker bursts %d, honest grants %d", attacks, honestOK)
			if honestOK < 30 {
				t.Errorf("honest requester got %d grants in an hour, attacker %d", honestOK, attacks)
			}
		})
	}
}

// The cooldown of a host key stops growing at 16 times Cooldown.
func TestBurstBackoffCap(t *testing.T) {
	b := NewBudget(burstLimits())
	now := t0
	for i := range 8 {
		g, ok := b.Burst(Connector, hostA, 0, now, netip.Addr{})
		if !ok {
			t.Fatalf("burst %d refused 16 minutes after the last", i)
		}
		g.Done(now)
		// Only past the cap: a probe that is granted would start a burst.
		if i < 3 {
			now = now.Add(16 * time.Minute)
			continue
		}
		if _, ok := b.Burst(Connector, hostA, 0, now.Add(16*time.Minute-time.Second), netip.Addr{}); ok {
			t.Fatalf("burst %d: cooldown shorter than 16 minutes", i)
		}
		now = now.Add(16 * time.Minute)
	}
}

// The cooldown map forgets a key 2 x 16 x Cooldown after its last burst.
func TestBurstCoolPruned(t *testing.T) {
	l := burstLimits()
	l.PerMinute = 1000
	b := NewBudget(l)
	for i := range 100 {
		g, ok := b.Burst(Connector, netip.AddrFrom4([4]byte{198, 19, 9, byte(i)}), 0, t0.Add(time.Duration(i)*time.Second), netip.Addr{})
		if !ok {
			t.Fatal("burst refused")
		}
		g.Done(t0.Add(time.Duration(i) * time.Second))
	}
	b.Burst(Connector, hostB, 0, t0.Add(40*time.Minute), netip.Addr{})
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.cool) != 1 {
		t.Fatalf("cool holds %d keys after 40 minutes, want 1", len(b.cool))
	}
}

// Refused reports what Burst would refuse for a connector: the cooldown, the per-minute cap, the interval, the slot.
func TestBurstRefused(t *testing.T) {
	l := burstLimits()
	l.Interval = 0
	b := NewBudget(l)
	if b.Refused(hostA, t0) {
		t.Fatal("refused with nothing running")
	}
	for i := range l.PerMinute {
		g, ok := b.Burst(Connector, netip.AddrFrom4([4]byte{198, 19, 8, byte(i)}), 0, t0, netip.Addr{})
		if !ok {
			t.Fatal("burst refused")
		}
		g.Done(t0)
	}
	if !b.Refused(hostA, t0.Add(time.Second)) {
		t.Fatal("not refused at the per-minute cap")
	}
	l = burstLimits()
	l.Punches = 1
	b = NewBudget(l)
	g, _ := b.Burst(Connector, hostB, 0, t0, netip.Addr{})
	if !b.Refused(hostA, t0) {
		t.Fatal("not refused while the one slot runs")
	}
	g.Done(t0)
	if !b.Refused(hostA, t0.Add(l.Interval/2)) || b.Refused(hostA, t0.Add(l.Interval)) {
		t.Fatal("interval not mirrored")
	}
	if !b.Refused(hostB, t0.Add(l.Interval)) {
		t.Fatal("cooldown toward the host not mirrored")
	}
	l = burstLimits()
	l.PerTarget = 1
	b = NewBudget(l)
	b.Burst(Connector, hostA, 0, t0, netip.Addr{})
	if !b.Refused(hostA, t0.Add(time.Hour)) {
		t.Fatal("PerTarget not mirrored")
	}
}
