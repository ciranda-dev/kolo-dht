package kolodht

// Tests for the hole-punch abuse bounds. Those that use internal/netsim are simulation only.

import (
	"errors"
	"net"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"github.com/ciranda-dev/kolo-dht/internal/netsim"
	"github.com/ciranda-dev/kolo-dht/internal/punch"
	"github.com/ciranda-dev/kolo-dht/internal/records"
	"github.com/ciranda-dev/kolo-dht/internal/wire"
	koloid "github.com/ciranda-dev/kolo-id"
)

// randomWindow is how long a random punch probes in the simulator, plus a margin. Tests that wait for it run in a
// synctest bubble: their clock is virtual, so the 1 ms pace does not depend on the host's timers.
const randomWindow = time.Duration(punch.RandomTries)*time.Millisecond + time.Second

// announced starts servers and one full-cone announcer b of topic, bootstrapped to all of them, with a tap.
func announced(t *testing.T, seed uint64, servers int, cfg *Config) (*sim, *tap, []*Node, *Node, Topic) {
	t.Helper()
	ctx := testCtx(t, 10*time.Second)
	tp := &tap{}
	s := newSim(t, netsim.Config{Seed: seed, Tap: tp.add})
	var srvs []*Node
	for range servers {
		srvs = append(srvs, s.server())
	}
	if servers > 1 {
		bootstrap(t, ctx, srvs[1:], srvs[0])
	}
	b := s.peer(natKinds[1], cfg)
	bootstrap(t, ctx, srvs, b)
	topic := topicOf("punch-abuse")
	if err := b.Announce(ctx, topic); err != nil {
		t.Fatal(err)
	}
	return s, tp, srvs, b, topic
}

// sentTo counts the datagrams of tp to ip, after the first skip.
func sentTo(tp *tap, skip int, ip netip.Addr) int {
	n := 0
	for _, p := range tp.all()[skip:] {
		if p.To.Addr() == ip {
			n++
		}
	}
	return n
}

// punchReplies counts the PUNCH replies b sent to srv in tp, after the first skip; the tap shows b's own address.
func punchReplies(t *testing.T, tp *tap, skip int, b, srv *Node) int {
	size := len(encode(t, 9, &wire.PunchReply{}, 0))
	from, to, n := addrOf(b), addrOf(srv), 0
	for _, p := range tp.all()[skip:] {
		if p.From == from && p.To == to && p.Size == size {
			n++
		}
	}
	return n
}

// A PUNCH without the MAC of its storer's punch secret, with a wrong one, or replayed, is dropped: nothing goes
// to the address it names and no reply goes back.
func TestPunchNeedsMAC(t *testing.T) {
	checkGoroutines(t)
	cases := []struct {
		name  string
		class wire.Class
		// make returns the datagrams to inject, in order, with a pause between them.
		make func(t *testing.T, srv, b *Node, topic Topic, victim netip.AddrPort) [][]byte
		// probes and replies are what the victim and the storer may get.
		probes, replies int
	}{
		{"no MAC", wire.ClassRandom, func(t *testing.T, srv, b *Node, topic Topic, victim netip.AddrPort) [][]byte {
			p := &wire.Punch{Topic: topic, Target: b.key, Key: [32]byte{7}, Addr: victim, Class: wire.ClassRandom, PunchID: [8]byte{1}, Counter: 1 << 40}
			return [][]byte{encode(t, 9, p, 0)}
		}, 0, 0},
		{"wrong MAC", wire.ClassRandom, func(t *testing.T, srv, b *Node, topic Topic, victim netip.AddrPort) [][]byte {
			p := &wire.Punch{Topic: topic, Target: b.key, Key: [32]byte{7}, Addr: netip.AddrPortFrom(victim.Addr(), 1), Class: wire.ClassRandom, PunchID: [8]byte{1}}
			storerPunch(t, srv, b, topic, 9, p)
			p.Addr = victim // the MAC covers the address
			return [][]byte{encode(t, 9, p, 0)}
		}, 0, 0},
		{"MAC last byte wrong", wire.ClassRandom, func(t *testing.T, srv, b *Node, topic Topic, victim netip.AddrPort) [][]byte {
			p := &wire.Punch{Topic: topic, Target: b.key, Key: [32]byte{7}, Addr: victim, Class: wire.ClassRandom, PunchID: [8]byte{1}}
			storerPunch(t, srv, b, topic, 9, p)
			p.MAC[wire.MACSize-1] ^= 1
			return [][]byte{encode(t, 9, p, 0)}
		}, 0, 0},
		{"replay", wire.ClassConsistent, func(t *testing.T, srv, b *Node, topic Topic, victim netip.AddrPort) [][]byte {
			p := &wire.Punch{Topic: topic, Target: b.key, Key: [32]byte{7}, Addr: victim, Class: wire.ClassConsistent, PunchID: [8]byte{1}}
			d := storerPunch(t, srv, b, topic, 9, p)
			return [][]byte{d, d}
		}, 1, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				cfg := fastConfig(false)
				cfg.PunchTimeout = time.Second
				s, tp, srvs, b, topic := announced(t, 30, 1, cfg)
				victim := s.socket()
				skip := len(tp.all())
				for _, d := range c.make(t, srvs[0], b, topic, victim.Addr()) {
					s.net.Inject(addrOf(srvs[0]), storerView(b, topic), d)
					// The first punch session ends, so a replay could open it again.
					time.Sleep(cfg.PunchTimeout + 500*time.Millisecond)
				}
				if c.class == wire.ClassRandom {
					time.Sleep(randomWindow)
				}
				if got := sentTo(tp, skip, victim.Addr().Addr()); got != c.probes {
					t.Errorf("victim got %d datagrams, want %d", got, c.probes)
				}
				if got := punchReplies(t, tp, skip, b, srvs[0]); got != c.replies {
					t.Errorf("storer got %d PUNCH replies, want %d", got, c.replies)
				}
			})
		})
	}
}

// The bursts that PUNCH starts have a cooldown per storer and a cap per minute, even below MaxRandomPunches.
func TestPunchBurstBudget(t *testing.T) {
	checkGoroutines(t)
	for _, perMinute := range []bool{false, true} {
		t.Run(map[bool]string{false: "per storer", true: "per minute"}[perMinute], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				cfg := fastConfig(false)
				cfg.MaxRandomPunches, cfg.RandomPunchInterval = 2, time.Second
				if perMinute {
					cfg.MaxRandomPunchesPerMinute = 1
				}
				s, tp, srvs, b, topic := announced(t, 31, 2, cfg)
				v1, v2 := s.socket(), s.socket()
				second := srvs[0] // the same storer asks twice
				if perMinute {
					second = srvs[1]
				}
				skip := len(tp.all())
				for i, x := range []struct {
					srv    *Node
					victim *netsim.Conn
				}{{srvs[0], v1}, {second, v2}} {
					p := &wire.Punch{Topic: topic, Target: b.key, Key: [32]byte{byte(7 + i)}, Addr: x.victim.Addr(), Class: wire.ClassRandom, PunchID: [8]byte{byte(1 + i)}}
					s.net.Inject(addrOf(x.srv), storerView(b, topic), storerPunch(t, x.srv, b, topic, uint64(9+i), p))
				}
				time.Sleep(randomWindow)
				if n := sentTo(tp, skip, v1.Addr().Addr()); n == 0 {
					t.Fatal("first burst did not run")
				}
				if n := sentTo(tp, skip, v2.Addr().Addr()); n != 0 {
					t.Fatalf("second burst sent %d probes", n)
				}
			})
		})
	}
}

// A lying relay that calls the peer random cannot aim random-port probes at the IP of a record only it returned,
// even with the record's key, which signs its answer.
func TestLyingRelayRandomVictim(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		ctx := testCtx(t, 20*time.Second)
		tp := &tap{}
		s := newSim(t, netsim.Config{Seed: 32, Tap: tp.add})
		a := s.peer(natKinds[0], fastConfig(false))
		id, victim := ident(t), s.socket()
		relayAddr := fakeRelayOn(t, s.socket(), fakeAnswer{status: wire.StatusOK, class: wire.ClassRandom, ip: victim.Addr().Addr(), ids: []*koloid.Identity{id}})
		rec := Record{PublicKey: id.PublicKey(), Addr: victim.Addr(), relays: []relay{{server: relayAddr, addr: victim.Addr()}}}
		if _, err := a.Connect(ctx, rec); !errors.Is(err, ErrUnreachable) {
			t.Fatalf("Connect: %v, want ErrUnreachable", err)
		}
		time.Sleep(200 * time.Millisecond)
		// One probe leaves before the CONNECT, as for any relay.
		if n := sentTo(tp, 0, victim.Addr().Addr()); n > 1 {
			t.Fatalf("victim IP got %d datagrams", n)
		}
	})
}

// A peer IP is confirmed only by servers in two /16s; on loopback each server counts by its address.
func TestMergeConfirms(t *testing.T) {
	topic := topicOf("confirm")
	id := ident(t)
	peer := netip.MustParseAddr("203.0.113.9")
	at := func(port uint16) records.Record {
		r, err := records.Sign(id, [32]byte(topic), netip.AddrPortFrom(peer, port))
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	from := func(server string, rs ...records.Record) answer {
		lr := &wire.LookupReply{}
		for _, r := range rs {
			lr.Records = append(lr.Records, wire.Record{Key: r.Key, Addr: r.Addr, Sig: r.Sig})
		}
		return answer{addr: netip.MustParseAddrPort(server), reply: lr}
	}
	other, err := records.Sign(id, [32]byte(topic), netip.MustParseAddrPort("198.51.100.4:7"))
	if err != nil {
		t.Fatal(err)
	}
	n := &Node{}
	for _, c := range []struct {
		name    string
		answers []answer
		want    []bool
	}{
		{"one /16", []answer{from("198.18.1.1:4000", at(1000)), from("198.18.2.1:4000", at(1001))}, []bool{false, false}},
		{"one server twice", []answer{from("198.18.1.1:4000", at(1000), at(1001))}, []bool{false, false}},
		{"two /16s, ports differ", []answer{from("198.18.1.1:4000", at(1000)), from("198.19.2.1:4000", at(1001))}, []bool{true, true}},
		{"another IP", []answer{from("198.18.1.1:4000", at(1000)), from("198.19.2.1:4000", other)}, []bool{false, false}},
		{"loopback", []answer{from("127.0.0.1:4000", at(1000)), from("127.0.0.1:4001", at(1001))}, []bool{true, true}},
	} {
		recs, _ := n.merge(topic, c.answers)
		if len(recs) != 1 || len(recs[0].relays) != len(c.want) {
			t.Fatalf("%s: %+v", c.name, recs)
		}
		for i, rl := range recs[0].relays {
			if rl.confirmed != c.want[i] {
				t.Errorf("%s: relay %d confirmed %v, want %v", c.name, i, rl.confirmed, c.want[i])
			}
		}
	}
}

// Random-port probes toward one IP wait RandomPunchCooldown, though the interval has passed.
func TestConnectorBurstCooldown(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		ctx := testCtx(t, 30*time.Second)
		xc, yc := fastConfig(false), fastConfig(false)
		xc.RandomPunchInterval = time.Second
		yc.RandomPunchInterval, yc.RandomPunchCooldown = time.Second, time.Second
		_, x, y := pairSim(t, 33, nil, portRestricted, symmetric, xc, yc)
		topic := topicOf("cooldown")
		if err := connectPair(t, ctx, x, y, topic); err != nil {
			t.Fatal(err)
		}
		time.Sleep(1500 * time.Millisecond)
		recs, err := x.Lookup(ctx, topic)
		if err != nil || len(recs) != 1 {
			t.Fatalf("Lookup: %v, %v", recs, err)
		}
		if _, err := x.Connect(ctx, recs[0]); !errors.Is(err, ErrTryLater) {
			t.Fatalf("second burst toward the peer's IP: %v, want ErrTryLater", err)
		}
	})
}

// A lying relay listed first, whatever it answers, does not keep Connect from the honest relays behind it.
func TestLyingRelayFailover(t *testing.T) {
	checkGoroutines(t)
	for _, c := range []struct {
		name   string
		status wire.Status
	}{{"ok", wire.StatusOK}, {"try later", wire.StatusTryLater}, {"unreachable", wire.StatusUnreachable}} {
		t.Run(c.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx := testCtx(t, 30*time.Second)
				sm, a, b := pairSim(t, 34, nil, portRestricted, portRestricted, fastConfig(false), fastConfig(false))
				topic := topicOf("failover")
				if err := b.Announce(ctx, topic); err != nil {
					t.Fatal(err)
				}
				recs, err := a.Lookup(ctx, topic)
				if err != nil || len(recs) != 1 {
					t.Fatalf("Lookup: %v, %v", recs, err)
				}
				bad := recs[0]
				fake := fakeRelayWith(t, sm, c.status, wire.ClassConsistent)
				bad.relays = append([]relay{{server: fake, addr: bad.relays[0].addr}}, bad.relays...)[:maxRelays]
				began := time.Now()
				conn, err := a.Connect(ctx, bad)
				if err != nil {
					t.Fatalf("Connect: %v", err)
				}
				conn.Close()
				if d := time.Since(began); d >= a.cfg.PunchTimeout {
					t.Fatalf("Connect took %v, a whole PunchTimeout", d)
				}
			})
		})
	}
}

// A live birthday connection holds no socket of the budget, so a third one works while two live.
func TestLiveBirthdayConnsFreeSockets(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		ctx := testCtx(t, 60*time.Second)
		ac, bc := fastConfig(false), fastConfig(false)
		ac.RandomPunchInterval, ac.MaxPunchSockets = time.Second, punch.Sockets
		bc.RandomPunchInterval, bc.RandomPunchCooldown = time.Second, time.Second
		_, a, b := pairSim(t, 35, nil, symmetric, portRestricted, ac, bc)
		for i, name := range []string{"one", "two", "three"} {
			if i > 0 {
				time.Sleep(1500 * time.Millisecond)
			}
			topic := topicOf(name)
			if err := b.Announce(ctx, topic); err != nil {
				t.Fatal(err)
			}
			recs, err := a.Lookup(ctx, topic)
			if err != nil || len(recs) != 1 {
				t.Fatalf("Lookup: %v, %v", recs, err)
			}
			c, err := a.Connect(ctx, recs[0])
			if err != nil {
				t.Fatalf("connection %d: %v", i+1, err)
			}
			defer c.Close()
			if n := a.budget.Sockets(); n != 0 {
				t.Fatalf("connection %d up: %d sockets held", i+1, n)
			}
		}
	})
}

// One requester cannot take the announcer's random punch slot again and again: within RandomPunchCooldown it
// gets ErrTryLater, while another requester gets the slot.
func TestRequesterCooldown(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		ctx := testCtx(t, 60*time.Second)
		ac, bc := fastConfig(false), fastConfig(false)
		ac.RandomPunchInterval = time.Second
		bc.RandomPunchInterval, bc.RandomPunchCooldown = time.Second, 10*time.Second
		s, a, b := pairSim(t, 36, nil, symmetric, portRestricted, ac, bc)
		topic := topicOf("slot")
		if err := connectPair(t, ctx, a, b, topic); err != nil {
			t.Fatal(err)
		}
		time.Sleep(1500 * time.Millisecond)
		recs, err := a.Lookup(ctx, topic)
		if err != nil || len(recs) != 1 {
			t.Fatalf("Lookup: %v, %v", recs, err)
		}
		if _, err := a.Connect(ctx, recs[0]); !errors.Is(err, ErrTryLater) {
			t.Fatalf("same requester again: %v, want ErrTryLater", err)
		}
		c := s.peer(symmetric, ac)
		if err := c.Bootstrap(ctx, a.boot); err != nil {
			t.Fatal(err)
		}
		recs, err = c.Lookup(ctx, topic)
		if err != nil || len(recs) != 1 {
			t.Fatalf("Lookup: %v, %v", recs, err)
		}
		conn, err := c.Connect(ctx, recs[0])
		if err != nil {
			t.Fatalf("another requester: %v", err)
		}
		conn.Close()
	})
}

// A random announcer named a wrong address as a consistent requester sends it one probe at the default TTL;
// the keep-alive of holders the peer never reached stays at TTL 5.
func TestBirthdayWrongAddressTTL(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		s, tp, srvs, b, topic := announced(t, 37, 1, fastConfig(false))
		forceRandom(b)
		nobody := s.socket()
		skip := len(tp.all())
		p := &wire.Punch{Topic: topic, Target: b.key, Key: [32]byte{7}, Addr: nobody.Addr(), Class: wire.ClassConsistent, PunchID: [8]byte{1}}
		s.net.Inject(addrOf(srvs[0]), storerView(b, topic), storerPunch(t, srvs[0], b, topic, 9, p))
		time.Sleep(randomWindow)
		low, def := 0, 0
		for _, q := range tp.all()[skip:] {
			if q.To != nobody.Addr() {
				continue
			}
			if q.TTL == punch.LowTTL {
				low++
			} else {
				def++
			}
		}
		if low < punch.Sockets || def > 1 {
			t.Fatalf("wrong address got %d packets at TTL %d and %d at the default TTL", low, punch.LowTTL, def)
		}
	})
}

// A birthday socket takes a probe from the peer as proof only if it echoes our nonce.
func TestHolderProofNeedsEcho(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		s := newSim(t, netsim.Config{Seed: 38, Hops: 1}) // the peer is near, so TTL 5 reaches it
		n := s.peer(natKinds[0], fastConfig(false))
		peer := s.socket()
		n.mu.Lock()
		ss, ok := n.openSession([wire.PunchIDSize]byte{4}, peer.Addr())
		g, ok2 := n.budget.Acquire(punch.Connector, peer.Addr().Addr(), punch.Sockets-1, time.Now())
		n.mu.Unlock()
		if !ok || !ok2 {
			t.Fatalf("session %v, grant %v", ok, ok2)
		}
		defer n.closeSession(ss)
		defer g.Done(time.Time{})
		b, err := n.openBirthday(ss, peer.Addr(), g)
		if err != nil {
			t.Fatal(err)
		}
		defer b.close()
		// Answer the first probe from a holder, not from the node's socket.
		buf := make([]byte, 2048)
		var holder netip.AddrPort
		var nonce [wire.PunchIDSize]byte
		for !holder.IsValid() {
			peer.SetReadDeadline(time.Now().Add(2 * time.Second))
			k, from, err := peer.ReadFrom(buf)
			if err != nil {
				t.Fatal("no probe from a holder")
			}
			if _, m, err := wire.Decode(buf[:k]); err == nil && udpAddrPort(from) != addrOf(n) {
				holder, nonce = udpAddrPort(from), m.(*wire.Probe).Nonce
			}
		}
		answer := func(echo [wire.PunchIDSize]byte) bool {
			peer.WriteTo(encode(t, 0, &wire.Probe{PunchID: ss.pid, Nonce: [8]byte{9}, Echo: echo}, 0), net.UDPAddrFromAddrPort(holder))
			select {
			case p := <-ss.valid:
				return p.holder > 0
			case <-time.After(300 * time.Millisecond):
				return false
			}
		}
		if answer([8]byte{1}) {
			t.Fatal("a probe with a wrong echo proved the peer")
		}
		if !answer(nonce) {
			t.Fatal("a probe echoing our nonce did not prove the peer")
		}
	})
}

// Birthday sockets that fail to open give their budget back.
func TestOpenBirthdayFailureReleases(t *testing.T) {
	checkGoroutines(t)
	n := loopNode(t, fastConfig(false))
	n.listen = func() (net.PacketConn, error) { return nil, errors.New("kolodht: no socket") }
	peer := netip.MustParseAddrPort("127.0.0.1:9")
	n.mu.Lock()
	ss, _ := n.openSession([wire.PunchIDSize]byte{5}, peer)
	g, ok := n.budget.Acquire(punch.Connector, peer.Addr(), punch.Sockets-1, time.Now())
	n.mu.Unlock()
	if !ok {
		t.Fatal("grant refused")
	}
	defer n.closeSession(ss)
	defer g.Done(time.Time{})
	if _, err := n.openBirthday(ss, peer, g); !errors.Is(err, ErrTryLater) {
		t.Fatalf("openBirthday: %v, want ErrTryLater", err)
	}
	if got := n.budget.Sockets(); got != 0 {
		t.Fatalf("%d sockets still counted", got)
	}
}
