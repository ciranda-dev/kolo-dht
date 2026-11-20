package kolodht

// NAT classifier tests over internal/netsim: lying servers, stale samples and a network change. Simulation only.

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/ciranda-dev/kolo-dht/internal/netsim"
	"github.com/ciranda-dev/kolo-dht/internal/wire"
)

// liar starts a fake server in its own /24 that answers PING, FIND_NODE and LOOKUP as a server, reporting every
// requester at observed, and ignores everything else.
func (s *sim) liar(observed netip.AddrPort) netip.AddrPort {
	s.t.Helper()
	h, err := s.net.AddHost(s.ip(18))
	if err != nil {
		s.t.Fatal(err)
	}
	pc, err := h.ListenUDP(4000)
	if err != nil {
		s.t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 2048)
		for {
			k, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			id, m, err := wire.Decode(buf[:k])
			if err != nil {
				continue
			}
			f := wire.NewFlags(0, true)
			var reply wire.Message
			switch m.(type) {
			case *wire.Ping:
				reply = &wire.PingReply{Observed: observed, Flags: f}
			case *wire.FindNode:
				reply = &wire.FindNodeReply{Observed: observed, Flags: f}
			case *wire.Lookup:
				reply = &wire.LookupReply{Observed: observed, Flags: f}
			default:
				continue
			}
			if b, err := wire.Fit(id, reply, k); err == nil {
				pc.WriteTo(b, from)
			}
		}
	}()
	s.t.Cleanup(func() {
		pc.Close()
		wg.Wait()
	})
	return pc.Addr()
}

// classOf returns n's class, the address more than half of its samples report (if any), and its sample count.
func classOf(n *Node) (wire.Class, netip.AddrPort, int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	c := n.nat.class(time.Now())
	count := map[netip.AddrPort]int{}
	var maj netip.AddrPort
	for _, x := range n.nat.samples {
		if count[x.observed]++; 2*count[x.observed] > len(n.nat.samples) {
			maj = x.observed
		}
	}
	return c, maj, len(n.nat.samples)
}

// TestSimLiars bootstraps a port-restricted peer from honest servers and servers that lie about its address, then
// checks its class, the address it announces, and that a public peer connects to it.
func TestSimLiars(t *testing.T) {
	checkGoroutines(t)
	lie := netip.MustParseAddrPort("198.18.254.1:1")
	tests := []struct {
		name          string
		honest, liars int
		want          wire.Class
		announces     bool
	}{
		{"one liar, one honest", 1, 1, wire.ClassUnknown, true},
		{"one liar, two honest", 2, 1, wire.ClassConsistent, true},
		{"one liar, three honest", 3, 1, wire.ClassConsistent, true},
		{"two liars, two honest", 2, 2, wire.ClassRandom, false},
		{"two liars, three honest", 3, 2, wire.ClassConsistent, true},
		{"two liars, six honest", 6, 2, wire.ClassConsistent, true},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx := testCtx(t, 30*time.Second)
				s := newSim(t, netsim.Config{Seed: uint64(40 + i)})
				var servers []*Node
				var all []netip.AddrPort
				for range tt.honest {
					srv := s.server()
					servers = append(servers, srv)
					all = append(all, addrOf(srv))
				}
				for range tt.liars {
					all = append(all, s.liar(lie))
				}
				a := s.peer(natKinds[0], fastConfig(false))
				b := s.peer(natKinds[3], fastConfig(false))
				bootstrap(t, ctx, servers, a)
				if err := b.Bootstrap(ctx, all); err != nil {
					t.Fatal(err)
				}
				c, maj, k := classOf(b)
				t.Logf("%d honest, %d liars: class %v, majority %v, %d samples", tt.honest, tt.liars, c, maj, k)
				if c != tt.want {
					t.Fatalf("class %v, want %v", c, tt.want)
				}
				if maj.IsValid() && maj == lie {
					t.Fatal("the liars' address is the majority")
				}
				if !tt.announces {
					// No address has a majority of the samples, not even an IP: nothing is signed.
					if err := b.Announce(ctx, topicOf("liars")); !errors.Is(err, ErrNotStored) {
						t.Fatalf("Announce: %v, want ErrNotStored", err)
					}
					t.Log("Announce: ErrNotStored")
					return
				}
				err := connectPair(t, ctx, a, b, topicOf("liars"))
				t.Logf("public peer connects: %v", err)
				if err != nil {
					t.Fatal(err)
				}
				b.mu.Lock()
				for _, st := range b.announces[topicOf("liars")].storers {
					if st.observed == lie {
						t.Error("announced at the liars' address")
					}
				}
				b.mu.Unlock()
			})
		})
	}
}

// clock is a NAT clock the test moves forward to expire mappings.
type clock struct{ off atomic.Int64 }

func (c *clock) now() time.Time        { return time.Now().Add(time.Duration(c.off.Load())) }
func (c *clock) skip(d time.Duration)  { c.off.Add(int64(d)) }
func changeNAT(c *clock, t *testing.T) { t.Helper(); c.skip(2 * time.Minute) }

// natPeer starts a peer behind a port-restricted NAT whose mappings expire after a minute of the test's clock without
// outbound traffic, and get a new random port: moving the clock is a network change.
func natPeer(s *sim, c *clock) *Node {
	s.t.Helper()
	nat, err := s.net.AddNAT(s.ip(19), netsim.NATConfig{Filtering: netsim.AddressPortDependentFiltering, Timeout: time.Minute})
	if err != nil {
		s.t.Fatal(err)
	}
	h, err := nat.AddHost(netip.MustParseAddr("10.0.0.2"))
	if err != nil {
		s.t.Fatal(err)
	}
	pc, err := h.ListenUDP(5000)
	if err != nil {
		s.t.Fatal(err)
	}
	return s.start(pc, fastConfig(false), -1)
}

// waitFor polls cond every 20ms until it holds or d passes, and returns the time it took.
func waitFor(t *testing.T, d time.Duration, cond func() bool) (time.Duration, bool) {
	t.Helper()
	start := time.Now()
	for time.Since(start) < d {
		if cond() {
			return time.Since(start), true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return d, false
}

// TestSimStaleSamples changes the network of a peer whose window holds 8 samples, after two of its servers went
// offline: the 6 servers left report the new address, and the 2 stale samples must not make the mapping random.
func TestSimStaleSamples(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		ctx := testCtx(t, 30*time.Second)
		var c clock
		s := newSim(t, netsim.Config{Seed: 50, Now: c.now})
		var servers []*Node
		for range 8 {
			servers = append(servers, s.server())
		}
		n := natPeer(s, &c)
		bootstrap(t, ctx, servers, n)
		_, before, k := classOf(n)
		if k != 8 {
			t.Fatalf("%d samples after bootstrap", k)
		}
		servers[0].Close()
		servers[1].Close()
		changeNAT(&c, t)
		bootstrap(t, ctx, servers[2:], n)
		cl, after, k := classOf(n)
		t.Logf("address %v -> %v: class %v from %d samples", before, after, cl, k)
		if cl != wire.ClassConsistent || after == before || k != 6 {
			t.Fatalf("after the change: class %v at %v from %d samples, want consistent at a new address from 6", cl, after, k)
		}
	})
}

// TestSimNetworkChange changes the network of an announcing peer and measures how long until its class settles on the
// new address: through a new majority (8 servers), and through sample age (3 servers, 2 gone after the change).
func TestSimNetworkChange(t *testing.T) {
	checkGoroutines(t)
	t.Run("new majority", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx := testCtx(t, 30*time.Second)
			var c clock
			s := newSim(t, netsim.Config{Seed: 51, Now: c.now})
			var servers []*Node
			for range 8 {
				servers = append(servers, s.server())
			}
			a, b := s.peer(natKinds[0], fastConfig(false)), natPeer(s, &c)
			bootstrap(t, ctx, servers, a, b)
			topic := topicOf("change")
			if err := b.Announce(ctx, topic); err != nil {
				t.Fatal(err)
			}
			_, old, _ := classOf(b)
			changeNAT(&c, t)
			d, ok := waitFor(t, 10*time.Second, func() bool {
				cl, ap, k := classOf(b)
				return cl == wire.ClassConsistent && ap != old && k >= 3 && onlyAddr(b, ap)
			})
			cl, now, k := classOf(b)
			t.Logf("settled on %v in %v (relookup every %v): class %v from %d samples", now, d.Round(time.Millisecond), simTiming.relookup, cl, k)
			if !ok {
				t.Fatalf("not settled: class %v at %v from %d samples", cl, now, k)
			}
			connectAfterChange(t, ctx, a, b, topic, now)
		})
	})
	t.Run("age", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx := testCtx(t, 30*time.Second)
			var c clock
			s := newSim(t, netsim.Config{Seed: 52, Now: c.now})
			servers := []*Node{s.server(), s.server(), s.server()}
			bootstrap(t, ctx, servers[1:], servers[0])
			a, b := s.peer(natKinds[0], fastConfig(false)), natPeer(s, &c)
			b.mu.Lock()
			b.nat.age = 4 * time.Second
			b.mu.Unlock()
			bootstrap(t, ctx, servers, a, b)
			topic := topicOf("change-age")
			if err := b.Announce(ctx, topic); err != nil {
				t.Fatal(err)
			}
			_, old, _ := classOf(b)
			servers[1].Close()
			servers[2].Close()
			changeNAT(&c, t)
			start := time.Now()
			d, ok := waitFor(t, 15*time.Second, func() bool {
				b.mu.Lock()
				defer b.mu.Unlock()
				return len(b.nat.samples) > 0 && !b.nat.observed(old) && b.nat.trusted(b.nat.samples[0].observed, time.Now())
			})
			b.mu.Lock()
			var now netip.AddrPort
			if len(b.nat.samples) > 0 {
				now = b.nat.samples[0].observed
			}
			k := len(b.nat.samples)
			b.mu.Unlock()
			t.Logf("old address gone after %v (sample age %v): trusts %v from %d samples", d.Round(time.Millisecond), 4*time.Second, now, k)
			if !ok || now == old {
				t.Fatalf("old address still held after %v", time.Since(start))
			}
			connectAfterChange(t, ctx, a, b, topic, now)
		})
	})
}

// onlyAddr reports whether every sample of n reports ap.
func onlyAddr(n *Node, ap netip.AddrPort) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, x := range n.nat.samples {
		if x.observed != ap {
			return false
		}
	}
	return true
}

// connectAfterChange waits until a finds b's record at its new address now, then connects to it.
func connectAfterChange(t *testing.T, ctx context.Context, a, b *Node, topic Topic, now netip.AddrPort) {
	t.Helper()
	start := time.Now()
	var recs []Record
	_, ok := waitFor(t, 15*time.Second, func() bool {
		var err error
		recs, err = a.Lookup(ctx, topic)
		return err == nil && len(recs) == 1 && recs[0].Addr == now
	})
	if !ok {
		t.Fatalf("record not at the new address %v: %+v", now, recs)
	}
	cn, err := a.Connect(ctx, recs[0])
	if err != nil && !errors.Is(err, ErrUnreachable) {
		t.Fatal(err)
	}
	t.Logf("record at the new address after %v; Connect: %v", time.Since(start).Round(time.Millisecond), err)
	if err != nil {
		t.Fatal(err)
	}
	cn.Close()
}
