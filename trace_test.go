package kolodht

import (
	"fmt"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/ciranda-dev/kolo-dht/internal/netsim"
	"github.com/ciranda-dev/kolo-dht/internal/punch"
)

type traces struct {
	mu  sync.Mutex
	evs []TraceEvent
	// node, when set, is called from the callback, so a trace sent with mu held deadlocks the test.
	node atomic.Pointer[Node]
}

func (t *traces) add(e TraceEvent) {
	if n := t.node.Load(); n != nil {
		n.Stats()
	}
	t.mu.Lock()
	t.evs = append(t.evs, e)
	t.mu.Unlock()
}

func (t *traces) all() []TraceEvent {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]TraceEvent(nil), t.evs...)
}

func (t *traces) count(f func(TraceEvent) bool) int {
	k := 0
	for _, e := range t.all() {
		if f(e) {
			k++
		}
	}
	return k
}

func traced(server bool, t *traces) *Config {
	c := fastConfig(server)
	c.Trace = t.add
	return c
}

// A Trace callback that panics drops its event: the punch still connects and the process lives.
func TestTracePanicContained(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t, 20*time.Second)
	srv := loopNode(t, fastConfig(true))
	var calls atomic.Int32
	cfg := func() *Config {
		c := fastConfig(false)
		c.Trace = func(TraceEvent) {
			calls.Add(1)
			panic("trace callback")
		}
		return c
	}
	a, b := loopNode(t, cfg()), loopNode(t, cfg())
	bootstrap(t, ctx, []*Node{srv}, a, b)
	if err := connectPair(t, ctx, a, b, topicOf("trace panic")); err != nil {
		t.Fatal(err)
	}
	if calls.Load() == 0 {
		t.Fatal("the panicking Trace was never called")
	}
}

// TestTraceLoopback: two consistent peers on loopback report each probe with its sockets, size and default TTL, the
// probe the other side received, and the proof the connector dials.
func TestTraceLoopback(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t, 20*time.Second)
	srv := loopNode(t, fastConfig(true))
	var ta, tb traces
	a, b := loopNode(t, traced(false, &ta)), loopNode(t, traced(false, &tb))
	ta.node.Store(a)
	tb.node.Store(b)
	bootstrap(t, ctx, []*Node{srv}, a, b)
	if err := connectPair(t, ctx, a, b, topicOf("trace")); err != nil {
		t.Fatal(err)
	}
	if ta.count(func(e TraceEvent) bool {
		return e.Kind == TraceProbeSent && e.Local == addrOf(a) && e.Remote == addrOf(b) && e.Size == probeSize && e.TTL == 0
	}) == 0 {
		t.Fatalf("connector traced no probe to the peer: %v", ta.all())
	}
	if tb.count(func(e TraceEvent) bool {
		return e.Kind == TraceProbeReceived && e.Local == addrOf(b) && e.Remote == addrOf(a) && e.Size > 0
	}) == 0 {
		t.Fatalf("announcer traced no probe from the connector: %v", tb.all())
	}
	if ta.count(func(e TraceEvent) bool { return e.Kind == TraceProved && e.Remote == addrOf(b) }) == 0 {
		t.Fatalf("connector traced no proof: %v", ta.all())
	}
	for _, e := range append(ta.all(), tb.all()...) {
		if e.Remote == addrOf(srv) {
			t.Fatalf("traced a DHT request as a probe: %v", e)
		}
	}
}

// TestSimTraceBirthday: the random side traces its 256 sockets and a TTL 5 probe from each of its 255 new ones, and the
// consistent side traces its random-port window and exactly the probes the network carried to the random side's IP.
func TestSimTraceBirthday(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		ctx := testCtx(t, 30*time.Second)
		tp := &tap{}
		var ta, tb traces
		_, a, b := pairSim(t, 9, tp, portRestricted, symmetric, traced(false, &ta), traced(false, &tb))
		ta.node.Store(a)
		tb.node.Store(b)
		aAddr := observedAddr(t, a)
		b.mu.Lock()
		bIP, _ := b.nat.publicIP()
		b.mu.Unlock()
		start := len(tp.all())
		if err := connectPair(t, ctx, a, b, topicOf("birthday")); err != nil {
			t.Fatal(err)
		}
		if tb.count(func(e TraceEvent) bool {
			return e.Kind == TraceBirthdayOpened && e.Count == punch.Sockets && e.Remote == aAddr
		}) != 1 {
			t.Fatalf("random side traced no birthday of %d sockets to %v", punch.Sockets, aAddr)
		}
		low := map[netip.AddrPort]bool{}
		for _, e := range tb.all() {
			if e.Kind == TraceProbeSent && e.TTL == punch.LowTTL && e.Remote == aAddr && e.Size == probeSize {
				low[e.Local] = true
			}
		}
		if len(low) != punch.Sockets-1 {
			t.Fatalf("TTL 5 probes traced from %d sockets, want %d", len(low), punch.Sockets-1)
		}
		if ta.count(func(e TraceEvent) bool {
			return e.Kind == TraceRandomProbes && e.Count == punch.RandomTries && e.Remote == netip.AddrPortFrom(bIP, 0)
		}) != 1 {
			t.Fatal("consistent side traced no random-port window")
		}
		// Every probe the network carried to the random side is traced, except on a port that reached us: the connection
		// then uses it, and a QUIC packet can have a probe's size.
		time.Sleep(50 * time.Millisecond)
		won := map[uint16]bool{}
		sent := map[netip.AddrPort]int{}
		for _, e := range ta.all() {
			switch {
			case e.Kind == TraceProbeReceived && e.Remote.Addr() == bIP:
				won[e.Remote.Port()] = true
			case e.Kind == TraceProbeSent && e.Remote.Addr() == bIP && e.Local == addrOf(a):
				sent[e.Remote]++
			}
		}
		carried := map[netip.AddrPort]int{}
		for _, p := range tp.all()[start:] {
			if p.From == addrOf(a) && p.To.Addr() == bIP && p.Size == probeSize {
				carried[p.To]++
			}
		}
		if len(sent) < 2 {
			t.Fatalf("traced probes to %d ports of the random side", len(sent))
		}
		for to, k := range carried {
			if won[to.Port()] && sent[to] > 0 && sent[to] <= k {
				continue
			}
			if sent[to] != k {
				t.Fatalf("traced %d probes to %v, the network carried %d", sent[to], to, k)
			}
		}
		if ta.count(func(e TraceEvent) bool { return e.Kind == TraceProved })+tb.count(func(e TraceEvent) bool { return e.Kind == TraceProved }) == 0 {
			t.Fatal("no side traced a proof")
		}
	})
}

// TestSimTraceDemo prints a birthday punch with the real odds, one line per event, for KOLODHT_TRACE=1 go test -v
// -run TestSimTraceDemo. Simulation only.
func TestSimTraceDemo(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		if os.Getenv("KOLODHT_TRACE") == "" {
			t.Skip("set KOLODHT_TRACE=1 to print a simulated birthday punch")
		}
		ctx := testCtx(t, 60*time.Second)
		print := func(side string) func(TraceEvent) {
			return func(e TraceEvent) { fmt.Printf("%s %s\n", side, e) }
		}
		ca, cb := fastConfig(false), fastConfig(false)
		ca.Trace, cb.Trace = print("consistent"), print("random    ")
		s := newSim(t, netsim.Config{Seed: 1})
		s.odds = true
		servers := []*Node{s.server(), s.server(), s.server()}
		bootstrap(t, ctx, servers[1:], servers[0])
		a, b := s.peer(portRestricted, ca), s.peer(symmetric, cb)
		bootstrap(t, ctx, servers, a, b)
		if err := connectPair(t, ctx, a, b, topicOf("demo")); err != nil {
			t.Fatal(err)
		}
		fmt.Println("connected")
	})
}

func TestTraceKindString(t *testing.T) {
	for k, want := range map[TraceKind]string{
		TraceProbeSent: "probe sent", TraceProbeReceived: "probe received", TraceBirthdayOpened: "birthday opened",
		TraceRandomProbes: "random probes", TraceProved: "proved", 0: "TraceKind(0)",
	} {
		if k.String() != want {
			t.Errorf("%d: %q, want %q", k, k.String(), want)
		}
	}
	e := TraceEvent{Kind: TraceProbeSent, Local: netip.MustParseAddrPort("0.0.0.0:49472"), Remote: netip.MustParseAddrPort("203.0.113.7:37330"), Size: 35, TTL: 5}
	if got, want := e.String(), "Sending 35b to 203.0.113.7:37330 from port 49472 (TTL 5)"; got != want {
		t.Errorf("%q, want %q", got, want)
	}
}
