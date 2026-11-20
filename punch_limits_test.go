package kolodht

// Tests for the hole-punch limits and replay protection. Those that use internal/netsim are simulation only.

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	mrand "math/rand/v2"
	"net"
	"net/netip"
	"slices"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/ciranda-dev/kolo-dht/internal/netsim"
	"github.com/ciranda-dev/kolo-dht/internal/punch"
	"github.com/ciranda-dev/kolo-dht/internal/records"
	"github.com/ciranda-dev/kolo-dht/internal/table"
	"github.com/ciranda-dev/kolo-dht/internal/wire"
	koloid "github.com/ciranda-dev/kolo-id"
	kolosecure "github.com/ciranda-dev/kolo-secure"
)

// socketIn opens a plain socket on a new public host in 198.prefix.0.0/16.
func (s *sim) socketIn(prefix byte) *netsim.Conn {
	s.t.Helper()
	h, err := s.net.AddHost(s.ip(prefix))
	if err != nil {
		s.t.Fatal(err)
	}
	pc, err := h.ListenUDP(4000)
	if err != nil {
		s.t.Fatal(err)
	}
	s.t.Cleanup(func() { pc.Close() })
	return pc
}

// server16 starts a public server in 198.18.0.0/16 only.
func (s *sim) server16() *Node {
	s.t.Helper()
	h, err := s.net.AddHost(s.ip(18))
	if err != nil {
		s.t.Fatal(err)
	}
	pc, err := h.ListenUDP(4000)
	if err != nil {
		s.t.Fatal(err)
	}
	return s.start(pc, fastConfig(true), s.next)
}

// newDH returns a new X25519 key and its share, as a storer makes at New.
func newDH(t *testing.T) (*ecdh.PrivateKey, [wire.ShareSize]byte) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k, [wire.ShareSize]byte(k.PublicKey().Bytes())
}

// colluders starts two fake relays in two /16s that answer a, and returns a confirmed record of id at victim.
func colluders(t *testing.T, s *sim, id *koloid.Identity, victim netip.AddrPort, a fakeAnswer) Record {
	rec := Record{PublicKey: id.PublicKey(), Addr: victim}
	for _, prefix := range []byte{21, 22} {
		rec.relays = append(rec.relays, relay{server: fakeRelayOn(t, s.socketIn(prefix), a), addr: victim, confirmed: true})
	}
	return rec
}

// A lying relay that answers "OK, random" without forwarding is skipped at once; the honest relay behind it connects.
func TestLyingRelayRandomPeer(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		ctx := testCtx(t, 30*time.Second)
		sm, a, b := pairSim(t, 44, nil, portRestricted, symmetric, fastConfig(false), fastConfig(false))
		topic := topicOf("failover-random")
		if err := b.Announce(ctx, topic); err != nil {
			t.Fatal(err)
		}
		recs, err := a.Lookup(ctx, topic)
		if err != nil || len(recs) != 1 || !recs[0].relays[0].confirmed {
			t.Fatalf("Lookup: %+v, %v", recs, err)
		}
		rec := recs[0]
		liar := relay{server: fakeRelayWith(t, sm, wire.StatusOK, wire.ClassRandom), addr: rec.relays[0].addr, confirmed: true}
		rec.relays = append([]relay{liar}, rec.relays...)[:maxRelays]
		began := time.Now()
		c, err := a.Connect(ctx, rec)
		if err != nil {
			t.Fatalf("Connect: %v after %v", err, time.Since(began))
		}
		c.Close()
		if d := time.Since(began); d >= a.cfg.PunchTimeout {
			t.Fatalf("Connect took %v, a whole PunchTimeout", d)
		}
	})
}

// Colluding servers in two /16s that replay a peer's record for a victim IP cannot get the peer's signature for that
// IP, so the connector sends the victim no random-port probe.
func TestReplayedRecordNoProbes(t *testing.T) {
	checkGoroutines(t)
	for _, c := range []struct {
		name   string
		ip     netip.Addr // the IP the peer signs for, if any
		old    bool       // the signature is of another punch
		signed wire.Class // the class the peer signed, if the relay changed it
	}{
		{"unsigned", netip.Addr{}, false, 0},
		{"signed for the peer's current IP", netip.MustParseAddr("198.23.0.1"), false, 0},
		{"signature of another punch", netip.Addr{}, true, 0},
		{"class changed by the relay", netip.Addr{}, false, wire.ClassConsistent},
	} {
		t.Run(c.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx := testCtx(t, 20*time.Second)
				tp := &tap{}
				s := newSim(t, netsim.Config{Seed: 45, Tap: tp.add})
				a := s.peer(natKinds[0], fastConfig(false))
				owner, victim := ident(t), s.socket()
				ans := fakeAnswer{status: wire.StatusOK, class: wire.ClassRandom, ip: c.ip, stale: c.old, signed: c.signed}
				switch {
				case c.old, c.signed != wire.ClassUnknown:
					ans.ids, ans.ip = []*koloid.Identity{owner}, victim.Addr().Addr()
				case c.ip.IsValid():
					ans.ids = []*koloid.Identity{owner}
				}
				rec := colluders(t, s, owner, victim.Addr(), ans)
				if _, err := a.Connect(ctx, rec); !errors.Is(err, ErrUnreachable) {
					t.Fatalf("Connect: %v, want ErrUnreachable", err)
				}
				time.Sleep(200 * time.Millisecond)
				// One probe leaves before each CONNECT, as for any relay.
				if n := sentTo(tp, 0, victim.Addr().Addr()); n > len(rec.relays) {
					t.Fatalf("victim IP got %d datagrams", n)
				}
			})
		})
	}
}

// The accepted limit: two colluding servers with a record they signed get one window of random-port probes sent to
// a victim IP; Connect never gives them a second, and the next Connect waits RandomPunchCooldown.
func TestSelfSignedRecordBound(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		ctx := testCtx(t, 30*time.Second)
		tp := &tap{}
		s := newSim(t, netsim.Config{Seed: 46, Tap: tp.add})
		cfg := fastConfig(false)
		cfg.RandomPunchInterval = time.Second
		a := s.peer(natKinds[0], cfg)
		attacker, victim := ident(t), s.socket()
		rec := colluders(t, s, attacker, victim.Addr(), fakeAnswer{status: wire.StatusOK, class: wire.ClassRandom, ip: victim.Addr().Addr(), ids: []*koloid.Identity{attacker}})
		if _, err := a.Connect(ctx, rec); !errors.Is(err, ErrUnreachable) {
			t.Fatalf("first Connect: %v, want ErrUnreachable", err)
		}
		first := sentTo(tp, 0, victim.Addr().Addr())
		if first == 0 || first > punch.RandomTries+len(rec.relays) {
			t.Fatalf("victim got %d datagrams from one Connect", first)
		}
		time.Sleep(1500 * time.Millisecond)
		if _, err := a.Connect(ctx, rec); !errors.Is(err, ErrTryLater) {
			t.Fatalf("second Connect: %v, want ErrTryLater", err)
		}
		if n := sentTo(tp, 0, victim.Addr().Addr()) - first; n > len(rec.relays) {
			t.Fatalf("second Connect sent the victim %d more datagrams", n)
		}
		t.Logf("victim got %d datagrams, %d bytes of probes", first, first*probeSize)
	})
}

// Only the K answers closest to the topic, by the IDs of our own lookup, count, so far servers cannot
// confirm a peer IP.
func TestMergeClosest(t *testing.T) {
	topic := topicOf("closest")
	target := table.ID(topic)
	id := ident(t)
	r, err := records.Sign(id, [32]byte(topic), netip.MustParseAddrPort("203.0.113.9:1000"))
	if err != nil {
		t.Fatal(err)
	}
	near := func(i int) answer {
		x := target
		x[31] ^= byte(i + 1)
		return answer{addr: netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 18, byte(i), 1}), 4000), id: x, reply: &wire.LookupReply{}}
	}
	far := func(prefix byte) answer {
		x := target
		for i := range x {
			x[i] ^= 0xff
		}
		lr := &wire.LookupReply{Records: []wire.Record{{Key: r.Key, Addr: r.Addr, Sig: r.Sig}}}
		return answer{addr: netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, prefix, 0, 1}), 4000), id: x, reply: lr}
	}
	n := &Node{}
	for _, c := range []struct {
		name  string
		near  int
		found bool
	}{{"beyond the K closest", table.K, false}, {"among the K closest", table.K - 2, true}} {
		answers := []answer{far(20), far(21)}
		for i := range c.near {
			answers = append(answers, near(i))
		}
		recs, _ := n.merge(topic, answers)
		if found := len(recs) == 1 && len(recs[0].relays) == 2 && recs[0].relays[0].confirmed; found != c.found {
			t.Errorf("%s: %+v", c.name, recs)
		}
	}
}

// The announcer's random punch slot comes back when its probes end, not at PunchTimeout.
func TestPunchSlotFreedWhenProbesEnd(t *testing.T) {
	checkGoroutines(t)
	for _, weDial := range []bool{false, true} {
		t.Run(map[bool]string{false: "random requester", true: "random announcer"}[weDial], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				cfg := fastConfig(false)
				cfg.PunchTimeout = 10 * time.Second
				s, _, srvs, b, topic := announced(t, 47, 1, cfg)
				class := wire.ClassRandom
				if weDial {
					forceRandom(b)
					class = wire.ClassConsistent
				}
				victim := s.socket()
				p := &wire.Punch{Topic: topic, Target: b.key, Key: [32]byte{7}, Addr: victim.Addr(), Class: class, PunchID: [8]byte{1}}
				s.net.Inject(addrOf(srvs[0]), storerView(b, topic), storerPunch(t, srvs[0], b, topic, 9, p))
				if _, ok := waitFor(t, time.Second, func() bool { return b.budget.Active() == 1 }); !ok {
					t.Fatal("the random punch did not start")
				}
				if _, ok := waitFor(t, randomWindow, func() bool { return b.budget.Active() == 0 }); !ok {
					t.Fatal("the random punch slot is still held after its probes ended")
				}
			})
		})
	}
}

// A burst that connected leaves both sides at RandomPunchCooldown, not the longer one of a failed burst.
func TestSuccessKeepsCooldown(t *testing.T) {
	checkGoroutines(t)
	for i, kinds := range [][2]natKind{{portRestricted, symmetric}, {symmetric, portRestricted}} {
		t.Run(kinds[0].name+" to "+kinds[1].name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx := testCtx(t, 30*time.Second)
				cfg := func() *Config {
					c := fastConfig(false)
					c.RandomPunchInterval, c.RandomPunchCooldown = time.Second, time.Second
					return c
				}
				_, a, b := pairSim(t, uint64(52+i), nil, kinds[0], kinds[1], cfg(), cfg())
				topic := topicOf("again")
				for round := range 2 {
					if err := connectPair(t, ctx, a, b, topic); err != nil {
						t.Fatalf("round %d: %v", round, err)
					}
					time.Sleep(1300 * time.Millisecond) // past Cooldown, not past twice it
				}
			})
		})
	}
}

// With all servers in one /16 no peer IP is confirmed: Connect returns ErrUnreachable and the announcer opens nothing.
func TestOneNetworkUnreachable(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		ctx := testCtx(t, 30*time.Second)
		s := newSim(t, netsim.Config{Seed: 42})
		servers := []*Node{s.server16(), s.server16(), s.server16()}
		bootstrap(t, ctx, servers[1:], servers[0])
		a, b := s.peer(portRestricted, fastConfig(false)), s.peer(symmetric, fastConfig(false))
		bootstrap(t, ctx, servers, a, b)
		topic := topicOf("one-net")
		if err := b.Announce(ctx, topic); err != nil {
			t.Fatal(err)
		}
		recs, err := a.Lookup(ctx, topic)
		if err != nil || len(recs) != 1 || recs[0].relays[0].confirmed {
			t.Fatalf("Lookup: %+v, %v", recs, err)
		}
		if _, err := a.Connect(ctx, recs[0]); !errors.Is(err, ErrUnreachable) {
			t.Fatalf("Connect: %v, want ErrUnreachable", err)
		}
		if b.budget.Sockets() != 0 || b.budget.Active() != 0 {
			t.Fatalf("announcer holds %d sockets and %d random punches", b.budget.Sockets(), b.budget.Active())
		}
	})
}

// Two honest PUNCHes of one storer that arrive out of order are both answered; a replay of either is not.
func TestPunchReorder(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		cfg := fastConfig(false)
		cfg.PunchTimeout = time.Second
		s, tp, srvs, b, topic := announced(t, 43, 1, cfg)
		v1, v2 := s.socket(), s.socket()
		p1 := &wire.Punch{Topic: topic, Target: b.key, Key: [32]byte{7}, Addr: v1.Addr(), Class: wire.ClassConsistent, PunchID: [8]byte{1}}
		p2 := &wire.Punch{Topic: topic, Target: b.key, Key: [32]byte{8}, Addr: v2.Addr(), Class: wire.ClassConsistent, PunchID: [8]byte{2}}
		d1 := storerPunch(t, srvs[0], b, topic, 9, p1)
		d2 := storerPunch(t, srvs[0], b, topic, 10, p2)
		skip := len(tp.all())
		for _, d := range [][]byte{d2, d1} {
			s.net.Inject(addrOf(srvs[0]), storerView(b, topic), d)
		}
		time.Sleep(cfg.PunchTimeout + 500*time.Millisecond)
		for _, d := range [][]byte{d2, d1} {
			s.net.Inject(addrOf(srvs[0]), storerView(b, topic), d)
		}
		time.Sleep(500 * time.Millisecond)
		if n := punchReplies(t, tp, skip, b, srvs[0]); n != 2 {
			t.Fatalf("storer got %d PUNCH replies, want 2", n)
		}
		if n1, n2 := sentTo(tp, skip, v1.Addr().Addr()), sentTo(tp, skip, v2.Addr().Addr()); n1 != 1 || n2 != 1 {
			t.Fatalf("requesters got %d and %d probes, want 1 each", n1, n2)
		}
	})
}

// The replay window takes each counter once, in any order within replayWindow, never 0 or one at or below the floor.
func TestReplayWindow(t *testing.T) {
	var r replay
	take := func(c uint64, want bool) {
		t.Helper()
		if got := r.take(c); got != want {
			t.Fatalf("take(%d) = %v, want %v", c, got, want)
		}
	}
	take(0, false)
	take(5, true)
	take(3, true)
	take(5, false)
	take(3, false)
	take(4, true)
	for c := uint64(100); c < 100+replayWindow; c++ {
		take(c, true)
	}
	take(5, false) // the floor: forgotten, so refused
	take(4, false)
	take(6, true) // never taken, above the floor
	take(6, false)
	take(100, false) // forgotten for 6, the new floor
	take(99, false)
	take(100+replayWindow-1, false)
	take(1000, true)
}

// The connector's cooldown toward an IP counts from the end of its probes, so a later relay of a Connect starts no window.
func TestConnectorCooldownFromEnd(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		ctx := testCtx(t, 30*time.Second)
		tp := &tap{}
		s := newSim(t, netsim.Config{Seed: 48, Tap: tp.add})
		cfg := fastConfig(false)
		cfg.PunchTimeout, cfg.RandomPunchInterval, cfg.RandomPunchCooldown = 4*time.Second, time.Second, 1500*time.Millisecond
		a := s.peer(natKinds[0], cfg)
		attacker, victim := ident(t), s.socket()
		rec := colluders(t, s, attacker, victim.Addr(), fakeAnswer{status: wire.StatusOK, class: wire.ClassRandom, ip: victim.Addr().Addr(), ids: []*koloid.Identity{attacker}})
		if _, err := a.Connect(ctx, rec); !errors.Is(err, ErrUnreachable) {
			t.Fatalf("Connect: %v, want ErrUnreachable", err)
		}
		if n := sentTo(tp, 0, victim.Addr().Addr()); n > punch.RandomTries+len(rec.relays) {
			t.Fatalf("victim got %d datagrams, more than one window", n)
		}
	})
}

// At most MaxPunches announcer connections on birthday sockets stay open; a new one never closes them.
func TestInboundBirthdayConnsBound(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		ctx := testCtx(t, 30*time.Second)
		bc := fastConfig(false)
		bc.MaxPunches, bc.RandomPunchInterval, bc.RandomPunchCooldown = 1, time.Second, time.Second
		s, a, b := pairSim(t, 49, nil, portRestricted, symmetric, fastConfig(false), bc)
		topic := topicOf("inbound")
		if err := b.Announce(ctx, topic); err != nil {
			t.Fatal(err)
		}
		recs, err := a.Lookup(ctx, topic)
		if err != nil || len(recs) != 1 {
			t.Fatalf("Lookup: %v, %v", recs, err)
		}
		ca, err := a.Connect(ctx, recs[0])
		if err != nil {
			t.Fatal(err)
		}
		defer ca.Close()
		cb, err := b.Accept(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer cb.Close()
		if cb.LocalAddr().(*net.UDPAddr).AddrPort().Port() == b.local.Port() {
			t.Skip("the node's own socket won the birthday punch")
		}
		held := func(want int) bool {
			_, ok := waitFor(t, 2*time.Second, func() bool {
				b.mu.Lock()
				defer b.mu.Unlock()
				return len(b.held) == want && len(b.pending) == 0 && b.punching == 0
			})
			return ok
		}
		if !held(1) {
			t.Fatal("the live birthday connection is not counted")
		}
		c := s.peer(portRestricted, fastConfig(false))
		if err := c.Bootstrap(ctx, a.boot); err != nil {
			t.Fatal(err)
		}
		if recs, err = c.Lookup(ctx, topic); err != nil || len(recs) != 1 {
			t.Fatalf("Lookup: %v, %v", recs, err)
		}
		// A full table refuses the next random punch as busy, before any socket opens, and keeps the held connection.
		time.Sleep(1100 * time.Millisecond) // past the interval and the storer's cooldown
		if _, err := c.Connect(ctx, recs[0]); !errors.Is(err, ErrTryLater) {
			t.Fatalf("Connect with MaxPunches connections held: %v, want ErrTryLater", err)
		}
		if cb.Context().Err() != nil {
			t.Fatal("the held connection was closed")
		}
		cb.Close()
		if !held(0) {
			t.Fatal("the closed birthday connection is still counted")
		}
	})
}

// A new lookup round that keeps a storer and its secret keeps the counters taken from it.
func TestRelookupKeepsReplay(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		ctx := testCtx(t, 10*time.Second)
		cfg := fastConfig(false)
		cfg.PunchTimeout = time.Second
		s, tp, srvs, b, topic := announced(t, 50, 1, cfg)
		v := s.socket()
		p := &wire.Punch{Topic: topic, Target: b.key, Key: [32]byte{7}, Addr: v.Addr(), Class: wire.ClassConsistent, PunchID: [8]byte{1}}
		d := storerPunch(t, srvs[0], b, topic, 9, p)
		skip := len(tp.all())
		s.net.Inject(addrOf(srvs[0]), storerView(b, topic), d)
		time.Sleep(cfg.PunchTimeout + 500*time.Millisecond)
		b.mu.Lock()
		ann := b.announces[topic]
		b.mu.Unlock()
		if err := b.announceRound(ctx, ann); err != nil {
			t.Fatal(err)
		}
		s.net.Inject(addrOf(srvs[0]), storerView(b, topic), d)
		time.Sleep(500 * time.Millisecond)
		if n := punchReplies(t, tp, skip, b, srvs[0]); n != 1 {
			t.Fatalf("storer got %d PUNCH replies, want 1", n)
		}
	})
}

// When either side's X25519 share changes both derive the new punch secret, so the storer's PUNCH is still taken.
func TestShareChange(t *testing.T) {
	checkGoroutines(t)
	for _, side := range []string{"storer", "announcer"} {
		t.Run(side, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx := testCtx(t, 10*time.Second)
				s, tp, srvs, b, topic := announced(t, 51, 1, fastConfig(false))
				srv := srvs[0]
				b.mu.Lock()
				ann := b.announces[topic]
				b.mu.Unlock()
				if side == "storer" {
					// A storer that restarts on the same address has a new key and an empty store.
					srv.mu.Lock()
					srv.dh, srv.dhShare = newDH(t)
					srv.store = newStoreTTL(srv, srv.tm.ttl)
					srv.mu.Unlock()
					b.refreshAll(ann)
				} else {
					// A storer dropped and found again gets a new key from us.
					b.mu.Lock()
					clear(ann.storers)
					b.mu.Unlock()
					if err := b.announceRound(ctx, ann); err != nil {
						t.Fatal(err)
					}
				}
				v := s.socket()
				p := &wire.Punch{Topic: topic, Target: b.key, Key: [32]byte{7}, Addr: v.Addr(), Class: wire.ClassConsistent, PunchID: [8]byte{1}}
				skip := len(tp.all())
				s.net.Inject(addrOf(srv), storerView(b, topic), storerPunch(t, srv, b, topic, 9, p))
				time.Sleep(500 * time.Millisecond)
				if n := punchReplies(t, tp, skip, b, srv); n != 1 {
					t.Fatalf("storer got %d PUNCH replies, want 1", n)
				}
			})
		})
	}
}

// A peer that signed "OK, consistent" but never probes back costs Connect one probe window, not PunchTimeout.
func TestConsistentGivesUpAfterWindow(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		ctx := testCtx(t, 20*time.Second)
		s := newSim(t, netsim.Config{Seed: 53})
		a := s.peer(natKinds[0], fastConfig(false))
		id, nobody := ident(t), s.socket()
		server := fakeRelayOn(t, s.socket(), fakeAnswer{status: wire.StatusOK, class: wire.ClassConsistent, ip: nobody.Addr().Addr(), ids: []*koloid.Identity{id}})
		rec := Record{PublicKey: id.PublicKey(), Addr: nobody.Addr(), relays: []relay{{server: server, addr: nobody.Addr()}}}
		began := time.Now()
		if _, err := a.Connect(ctx, rec); !errors.Is(err, ErrUnreachable) {
			t.Fatalf("Connect: %v, want ErrUnreachable", err)
		}
		if d := time.Since(began); d >= a.cfg.PunchTimeout/2 {
			t.Fatalf("Connect took %v", d)
		}
	})
}

// The punch secret, PUNCH MAC and signed PUNCH reply are the README's formats, contexts included.
func TestPunchFormats(t *testing.T) {
	priv, share := newDH(t)
	peer, peerShare := newDH(t)
	key, topic := [wire.KeySize]byte{1}, [32]byte{2}
	got, ok := punchSecret(priv, peerShare, share, peerShare, key, topic)
	shared, err := priv.ECDH(peer.PublicKey())
	if !ok || err != nil {
		t.Fatal(ok, err)
	}
	info := string(bytes.Join([][]byte{[]byte("kolo-dht/punch-secret/v1"), share[:], peerShare[:], key[:], topic[:]}, nil))
	if want, err := hkdf.Key(sha256.New, shared, nil, info, 32); err != nil || got != [32]byte(want) {
		t.Fatalf("punch secret %x, want %x", got, want)
	}
	p := &wire.Punch{Topic: topic, Target: key, Key: [32]byte{3}, Addr: netip.MustParseAddrPort("198.19.1.1:4000"), Class: wire.ClassRandom, PunchID: [8]byte{4}, Counter: 5}
	mac, ok := punchMAC(got, p)
	h := hmac.New(sha256.New, got[:])
	h.Write([]byte("kolo-dht/punch/v1"))
	h.Write(encode(t, 0, p, 0))
	if !ok || !bytes.Equal(mac[:], h.Sum(nil)) {
		t.Fatalf("PUNCH MAC %x", mac)
	}
	want := []byte{0, 4, 0, 0, 0, 0, 0, 0, 0, byte(wire.ClassRandom), 198, 19, 1, 1}
	if got := replySignable(p.PunchID, wire.ClassRandom, p.Addr.Addr()); !bytes.Equal(got, want) {
		t.Fatalf("signed reply %x, want %x", got, want)
	}
	if punchReplyContext != "kolo-dht/punch-reply/v1" {
		t.Fatalf("context %q", punchReplyContext)
	}
}

// A Connect whose random punch failed returns ErrUnreachable even if the next relay is refused by its cooldown.
func TestFailedPunchUnreachable(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		ctx := testCtx(t, 30*time.Second)
		s := newSim(t, netsim.Config{Seed: 47})
		cfg := fastConfig(false)
		cfg.RandomPunchInterval = time.Second
		a := s.peer(natKinds[0], cfg)
		peer, mute := ident(t), s.socket()
		rec := colluders(t, s, peer, mute.Addr(), fakeAnswer{status: wire.StatusOK, class: wire.ClassRandom, ip: mute.Addr().Addr(), ids: []*koloid.Identity{peer}})
		if _, err := a.Connect(ctx, rec); !errors.Is(err, ErrUnreachable) {
			t.Fatalf("Connect after a failed punch: %v, want ErrUnreachable", err)
		}
		if _, err := a.Connect(ctx, rec); !errors.Is(err, ErrTryLater) {
			t.Fatalf("Connect within the cooldown: %v, want ErrTryLater", err)
		}
	})
}

// A connection from another /24 with the peer's key is not the burst's success: the IP's cooldown still doubles.
func TestDialBackKeepsBackoff(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		ctx := testCtx(t, 30*time.Second)
		tp := &tap{}
		s := newSim(t, netsim.Config{Seed: 62, Tap: tp.add})
		cfg := fastConfig(false)
		cfg.RandomPunchInterval, cfg.RandomPunchCooldown, cfg.MaxRandomPunchesPerMinute = time.Second, time.Second, 64
		a := s.peer(natKinds[0], cfg)
		attacker := ident(t)
		h, err := s.net.AddHost(s.ip(23))
		if err != nil {
			t.Fatal(err)
		}
		pc, err := h.ListenUDP(4000)
		if err != nil {
			t.Fatal(err)
		}
		att, err := newConn(context.Background(), pc, func() (net.PacketConn, error) { return h.ListenUDP(0) }, attacker, fastConfig(false), simTiming, -1)
		if err != nil {
			t.Fatal(err)
		}
		defer att.Close()
		victim := s.socket()
		rec := colluders(t, s, attacker, victim.Addr(), fakeAnswer{status: wire.StatusOK, class: wire.ClassRandom, ip: victim.Addr().Addr(), ids: []*koloid.Identity{attacker}})
		go func() {
			time.Sleep(time.Second)
			if c, err := att.sl.Dial(ctx, addrOf(a), a.key[:]); err == nil {
				time.Sleep(100 * time.Millisecond)
				c.Close()
			}
		}()
		if c, err := a.Connect(ctx, rec); err == nil {
			c.Close()
		}
		first := sentTo(tp, 0, victim.Addr().Addr())
		time.Sleep(1300 * time.Millisecond)
		a.Connect(ctx, rec)
		if n := sentTo(tp, 0, victim.Addr().Addr()) - first; n > len(rec.relays) {
			t.Fatalf("a second window of %d probes toward the IP 1.3s after one the attacker reset by dialing back", n)
		}
	})
}

// A connector that would refuse its own random-port probes says no-random in CONNECT; Connect returns ErrTryLater.
func TestCoolingConnectorNoSockets(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		ctx := testCtx(t, 30*time.Second)
		_, a, b := pairSim(t, 50, nil, portRestricted, symmetric, fastConfig(false), fastConfig(false))
		topic := topicOf("cooling")
		if err := b.Announce(ctx, topic); err != nil {
			t.Fatal(err)
		}
		recs, err := a.Lookup(ctx, topic)
		if err != nil || len(recs) != 1 {
			t.Fatalf("Lookup: %v, %v", recs, err)
		}
		ip := recs[0].relays[0].addr.Addr()
		g, ok := a.budget.Burst(punch.Connector, ip, 0, time.Now(), netip.Addr{})
		if !ok {
			t.Fatal("seed burst refused")
		}
		g.Done(time.Now())
		if _, err := a.Connect(ctx, recs[0]); !errors.Is(err, ErrTryLater) {
			t.Fatalf("Connect within the cooldown: %v, want ErrTryLater", err)
		}
		if n := b.budget.Sockets(); n != 0 {
			t.Fatalf("the peer holds %d sockets for a connector that cannot probe", n)
		}
	})
}

// A counter that arrives after the 15 that follow it is still taken, once.
func TestReplayWindowSixteen(t *testing.T) {
	var r replay
	for c := uint64(2); c <= 16; c++ {
		if !r.take(c) {
			t.Fatalf("take(%d) refused", c)
		}
	}
	if !r.take(1) || r.take(1) {
		t.Fatal("a counter 15 places late is not taken exactly once")
	}
}

// A late counter that is never seen can not lower the floor, so a counter taken before is never taken again.
func TestReplayFloorNeverFalls(t *testing.T) {
	var r replay
	for c := uint64(102); c < 102+replayWindow; c++ {
		if !r.take(c) {
			t.Fatalf("take(%d) refused", c)
		}
	}
	if !r.take(100) {
		t.Fatal("take(100), never seen, refused")
	}
	if !r.take(118) {
		t.Fatal("take(118) refused")
	}
	if r.take(102) {
		t.Fatal("take(102) accepted a second time")
	}
	if r.take(100) {
		t.Fatal("take(100) accepted a second time")
	}
}

// For any order and repeats of counters, a counter is accepted at most once and the floor never goes down.
func TestReplayAcceptsOnce(t *testing.T) {
	rng := mrand.New(mrand.NewPCG(1, 2))
	for round := range 2000 {
		var r replay
		taken := map[uint64]bool{}
		floor := uint64(0)
		for range 400 {
			c := uint64(rng.IntN(3*replayWindow + 8))
			if rng.IntN(4) == 0 {
				c += uint64(rng.IntN(64))
			}
			if r.take(c) {
				if taken[c] {
					t.Fatalf("round %d: counter %d accepted twice", round, c)
				}
				taken[c] = true
			}
			if r.floor < floor {
				t.Fatalf("round %d: floor fell from %d to %d", round, floor, r.floor)
			}
			floor = r.floor
		}
	}
}

// Held birthday connections are never closed by a new one: past 4 from one /24, or MaxPunches in all, a punch is refused.
func TestHeldPerNetwork(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t, 10*time.Second)
	cfg := fastConfig(false)
	cfg.MaxPunches = 6
	b := loopNode(t, cfg)
	var held []*kolosecure.Conn
	for i := range 4 {
		b.mu.Lock()
		fits := b.canHold(netip.MustParseAddr("127.0.0.9"))
		b.mu.Unlock()
		if !fits {
			t.Fatalf("connection %d of one /24 refused", i+1)
		}
		if _, err := loopNode(t, fastConfig(false)).sl.Dial(ctx, addrOf(b), b.key[:]); err != nil {
			t.Fatal(err)
		}
		c, err := b.Accept(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		b.hold(c)
		held = append(held, c)
	}
	other := netip.MustParseAddr("198.51.100.7")
	b.mu.Lock()
	full, fits := b.canHold(netip.MustParseAddr("127.0.0.9")), b.canHold(other)
	b.pending = append(b.pending, other) // a birthday punch running for another /24
	last := b.canHold(other)
	b.pending = append(b.pending, other)
	none := b.canHold(netip.MustParseAddr("203.0.113.1"))
	b.mu.Unlock()
	if full || !fits || !last || none {
		t.Fatalf("canHold: 5th of one /24 %v, other /24 %v, 6th in all %v, 7th in all %v", full, fits, last, none)
	}
	for i, c := range held {
		if c.Context().Err() != nil {
			t.Fatalf("held connection %d was closed", i)
		}
	}
}

// A random announcer whose /24 table is full for the requester IP refuses the PUNCH before opening sockets.
func TestPunchRefusedWhenHeldFull(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		cfg := fastConfig(false)
		cfg.PunchTimeout = 10 * time.Second
		s, _, srvs, b, topic := announced(t, 55, 1, cfg)
		forceRandom(b)
		full, free := s.socket(), s.socket()
		b.mu.Lock()
		for range 4 {
			b.pending = append(b.pending, full.Addr().Addr())
		}
		b.mu.Unlock()
		try := func(id byte, to netip.AddrPort) bool {
			p := &wire.Punch{Topic: topic, Target: b.key, Key: [32]byte{7}, Addr: to, Class: wire.ClassConsistent, PunchID: [8]byte{id}}
			s.net.Inject(addrOf(srvs[0]), storerView(b, topic), storerPunch(t, srvs[0], b, topic, uint64(id), p))
			_, ok := waitFor(t, 500*time.Millisecond, func() bool { return b.budget.Active() == 1 })
			return ok
		}
		if try(1, full.Addr()) {
			t.Fatal("a punch for a full /24 opened sockets")
		}
		if !try(2, free.Addr()) {
			t.Fatal("a punch for another /24 was refused")
		}
		b.mu.Lock()
		b.pending = b.pending[4:]
		b.mu.Unlock()
	})
}

// A connector that cannot start a burst now (here, the interval after another random punch) says no-random in CONNECT.
func TestBusyConnectorNoSockets(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		ctx := testCtx(t, 30*time.Second)
		_, a, b := pairSim(t, 51, nil, portRestricted, symmetric, fastConfig(false), fastConfig(false))
		topic := topicOf("busy")
		if err := b.Announce(ctx, topic); err != nil {
			t.Fatal(err)
		}
		recs, err := a.Lookup(ctx, topic)
		if err != nil || len(recs) != 1 {
			t.Fatalf("Lookup: %v, %v", recs, err)
		}
		other := netip.MustParseAddr("198.51.100.7")
		g, ok := a.budget.Burst(punch.Connector, other, 0, time.Now(), netip.Addr{})
		if !ok {
			t.Fatal("seed burst refused")
		}
		g.Done(time.Now())
		if _, err := a.Connect(ctx, recs[0]); !errors.Is(err, ErrTryLater) {
			t.Fatalf("Connect within the interval: %v, want ErrTryLater", err)
		}
		if n := b.budget.Sockets(); n != 0 {
			t.Fatalf("the peer holds %d sockets for a connector that cannot probe", n)
		}
	})
}

// A punch that failed on one relay makes Connect return ErrUnreachable even if the next relay says the peer is busy.
func TestFailedPunchThenPeerBusy(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		ctx := testCtx(t, 30*time.Second)
		s := newSim(t, netsim.Config{Seed: 52})
		cfg := fastConfig(false)
		cfg.RandomPunchInterval = time.Second
		a := s.peer(natKinds[0], cfg)
		peer, mute := ident(t), s.socket()
		ok := fakeAnswer{status: wire.StatusOK, class: wire.ClassRandom, ip: mute.Addr().Addr(), ids: []*koloid.Identity{peer}}
		rec := Record{PublicKey: peer.PublicKey(), Addr: mute.Addr(), relays: []relay{
			{server: fakeRelayOn(t, s.socketIn(21), ok), addr: mute.Addr(), confirmed: true},
			{server: fakeRelayOn(t, s.socketIn(22), fakeAnswer{status: wire.StatusTryLater}), addr: mute.Addr(), confirmed: true},
		}}
		if _, err := a.Connect(ctx, rec); !errors.Is(err, ErrUnreachable) {
			t.Fatalf("Connect: %v, want ErrUnreachable", err)
		}
	})
}

// A lying storer that answers unreachable while this node cannot start a burst does not end Connect.
func TestLyingUnreachableWhileBusy(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		ctx := testCtx(t, 30*time.Second)
		sm, a, b := pairSim(t, 34, nil, portRestricted, portRestricted, fastConfig(false), fastConfig(false))
		topic := topicOf("busy-liar")
		if err := b.Announce(ctx, topic); err != nil {
			t.Fatal(err)
		}
		recs, err := a.Lookup(ctx, topic)
		if err != nil || len(recs) != 1 {
			t.Fatalf("Lookup: %v, %v", recs, err)
		}
		rec := recs[0]
		fake := fakeRelayWith(t, sm, wire.StatusUnreachable, wire.ClassConsistent)
		rec.relays = append([]relay{{server: fake, addr: rec.relays[0].addr, confirmed: true}}, rec.relays...)[:maxRelays]
		g, ok := a.budget.Burst(punch.Connector, netip.MustParseAddr("203.0.113.7"), 0, time.Now(), netip.Addr{})
		if !ok {
			t.Fatal("seed burst refused")
		}
		g.Done(time.Now())
		c, err := a.Connect(ctx, rec)
		if err != nil {
			t.Fatalf("Connect behind a lying relay while busy: %v", err)
		}
		c.Close()
	})
}

// The announcer counts a burst as connected only for a connection from the probed /24: a dial-back from another /24
// leaves the cooldown toward the requester IP growing.
func TestAnnouncerDialBack(t *testing.T) {
	checkGoroutines(t)
	for _, same := range []bool{false, true} {
		t.Run(map[bool]string{false: "other /24", true: "same /24"}[same], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx := testCtx(t, 20*time.Second)
				cfg := fastConfig(false)
				cfg.PunchTimeout, cfg.RandomPunchInterval, cfg.RandomPunchCooldown, cfg.MaxRandomPunchesPerMinute = 10*time.Second, time.Second, time.Second, 64
				s, _, srvs, b, topic := announced(t, 53, 1, cfg)
				victim := s.socket()
				ip := s.ip(24)
				if same {
					v := victim.Addr().Addr().As4()
					v[3] += 100
					ip = netip.AddrFrom4(v)
				}
				h, err := s.net.AddHost(ip)
				if err != nil {
					t.Fatal(err)
				}
				pc, err := h.ListenUDP(4000)
				if err != nil {
					t.Fatal(err)
				}
				attacker := ident(t)
				att, err := newConn(context.Background(), pc, func() (net.PacketConn, error) { return h.ListenUDP(0) }, attacker, fastConfig(false), simTiming, -1)
				if err != nil {
					t.Fatal(err)
				}
				defer att.Close()
				punchOnce := func(id byte) bool {
					p := &wire.Punch{Topic: topic, Target: b.key, Key: [32]byte(attacker.PublicKey()), Addr: victim.Addr(), Class: wire.ClassRandom, PunchID: [8]byte{id}}
					s.net.Inject(addrOf(srvs[0]), storerView(b, topic), storerPunch(t, srvs[0], b, topic, uint64(id), p))
					_, ok := waitFor(t, 500*time.Millisecond, func() bool { return b.budget.Active() == 1 })
					return ok
				}
				if !punchOnce(1) {
					t.Fatal("the first burst did not start")
				}
				c, err := att.sl.Dial(ctx, storerView(b, topic), b.key[:])
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				if _, ok := waitFor(t, 2*time.Second, func() bool { return b.budget.Active() == 0 }); !ok {
					t.Fatal("the burst did not end")
				}
				time.Sleep(1300 * time.Millisecond) // past Cooldown, not past twice it
				if got := punchOnce(2); got != same {
					t.Fatalf("second burst started = %v, want %v", got, same)
				}
			})
		})
	}
}

// The connector counts a burst as connected for a connection from the probed /24, as from a NAT pool's other address.
func TestConnectorSameNetDial(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		ctx := testCtx(t, 30*time.Second)
		s := newSim(t, netsim.Config{Seed: 54})
		cfg := fastConfig(false)
		cfg.RandomPunchInterval, cfg.RandomPunchCooldown, cfg.MaxRandomPunchesPerMinute = time.Second, time.Second, 64
		a := s.peer(natKinds[0], cfg)
		peer, mute := ident(t), s.socket()
		v := mute.Addr().Addr().As4()
		v[3] += 100
		h, err := s.net.AddHost(netip.AddrFrom4(v))
		if err != nil {
			t.Fatal(err)
		}
		pc, err := h.ListenUDP(4000)
		if err != nil {
			t.Fatal(err)
		}
		pn, err := newConn(context.Background(), pc, func() (net.PacketConn, error) { return h.ListenUDP(0) }, peer, fastConfig(false), simTiming, -1)
		if err != nil {
			t.Fatal(err)
		}
		defer pn.Close()
		rec := colluders(t, s, peer, mute.Addr(), fakeAnswer{status: wire.StatusOK, class: wire.ClassRandom, ip: mute.Addr().Addr(), ids: []*koloid.Identity{peer}})
		go func() {
			time.Sleep(time.Second)
			if c, err := pn.sl.Dial(ctx, addrOf(a), a.key[:]); err == nil {
				time.Sleep(100 * time.Millisecond)
				c.Close()
			}
		}()
		c, err := a.Connect(ctx, rec)
		if err != nil {
			t.Fatalf("Connect: %v", err)
		}
		c.Close()
		time.Sleep(1300 * time.Millisecond) // past Cooldown, not past twice it
		if a.budget.Refused(mute.Addr().Addr(), time.Now()) {
			t.Fatal("the cooldown grew after a connection from the probed /24")
		}
	})
}

// A random announcer counts a burst as connected only for a connection from the probed /24, also when the proof reached
// its own socket; one from another /24 leaves the IP's cooldown growing.
func TestRandomAnnouncerDialBack(t *testing.T) {
	checkGoroutines(t)
	for _, same := range []bool{false, true} {
		t.Run(map[bool]string{false: "other /24", true: "same /24"}[same], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx := testCtx(t, 30*time.Second)
				s := newSim(t, netsim.Config{Seed: 70})
				servers := []*Node{s.server(), s.server(), s.server()}
				bootstrap(t, ctx, servers[1:], servers[0])
				bc := fastConfig(false)
				bc.PunchTimeout, bc.RandomPunchInterval, bc.RandomPunchCooldown, bc.MaxRandomPunchesPerMinute = 10*time.Second, time.Second, time.Second, 64
				// Random mapping, open filtering: a host of the probed /24 reaches the mapping the punch opened toward the IP,
				// as from another address of a NAT pool.
				b := s.peer(natKind{"random-open", false, netsim.NATConfig{Mapping: netsim.AddressPortDependent, Filtering: netsim.EndpointIndependentFiltering}}, bc)
				bootstrap(t, ctx, servers, b)
				topic := topicOf("holder0")
				if err := b.Announce(ctx, topic); err != nil {
					t.Fatal(err)
				}
				b.mu.Lock()
				var srv *Node
				var bAddr netip.AddrPort
				for from, st := range b.announces[topic].storers {
					for _, x := range servers {
						if addrOf(x) == from {
							srv, bAddr = x, st.observed
						}
					}
				}
				random := b.nat.class(time.Now()) == wire.ClassRandom
				b.mu.Unlock()
				if !random || srv == nil {
					t.Fatal("need a random announcer and its storer")
				}
				vc := s.socket()
				v := vc.Addr()
				proof, to := srv, bAddr // answers from its own /24
				if same {
					ip := v.Addr().As4()
					ip[3] += 100
					h, err := s.net.AddHost(netip.AddrFrom4(ip))
					if err != nil {
						t.Fatal(err)
					}
					pc, err := h.ListenUDP(4000)
					if err != nil {
						t.Fatal(err)
					}
					if proof, err = newConn(context.Background(), pc, func() (net.PacketConn, error) { return h.ListenUDP(0) }, ident(t), fastConfig(false), simTiming, -1); err != nil {
						t.Fatal(err)
					}
					defer proof.Close()
				}
				punchOnce := func(id byte) bool {
					p := &wire.Punch{Topic: topic, Target: b.key, Key: proof.key, Addr: v, Class: wire.ClassConsistent, PunchID: [8]byte{id}}
					s.net.Inject(addrOf(srv), bAddr, storerPunch(t, srv, b, topic, uint64(id), p))
					_, ok := waitFor(t, 500*time.Millisecond, func() bool { return b.budget.Active() == 1 })
					return ok
				}
				if !punchOnce(1) {
					t.Fatal("the first burst did not start")
				}
				if same { // answer on the mapping toward the IP, which the IP's first datagram shows
					vc.SetReadDeadline(time.Now().Add(2 * time.Second))
					_, from, err := vc.ReadFrom(make([]byte, 2048))
					if err != nil {
						t.Fatal(err)
					}
					to = from.(*net.UDPAddr).AddrPort()
				}
				proof.mu.Lock()
				ss, ok := proof.openSession([8]byte{1}, to)
				proof.mu.Unlock()
				if !ok {
					t.Fatal("openSession")
				}
				proof.probe(ss, to)
				c, err := proof.Accept(ctx)
				if err != nil {
					t.Fatal(err)
				}
				c.Close()
				proof.closeSession(ss)
				if _, ok := waitFor(t, 2*time.Second, func() bool { return b.budget.Active() == 0 }); !ok {
					t.Fatal("the burst did not end")
				}
				b.mu.Lock()
				n := len(b.held)
				b.mu.Unlock()
				if n != 0 {
					t.Fatalf("held %d connections made on the node's own socket", n)
				}
				time.Sleep(1300 * time.Millisecond) // past Cooldown, not past twice it
				if got := punchOnce(2); got != same {
					t.Fatalf("second burst started = %v, want %v", got, same)
				}
			})
		})
	}
}

// A running birthday punch holds its place: with MaxRandomPunches 2, a second punch that would not fit is refused.
func TestBirthdayPunchReserves(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		cfg := fastConfig(false)
		cfg.PunchTimeout, cfg.MaxPunches, cfg.MaxRandomPunches, cfg.MaxRandomPunchesPerMinute = 10*time.Second, 2, 2, 64
		cfg.MaxPunchSockets = 2 * punch.Sockets
		s, _, srvs, b, topic := announced(t, 56, 2, cfg)
		forceRandom(b)
		b.mu.Lock()
		seen := map[netip.AddrPort]netip.AddrPort{}
		for from, st := range b.announces[topic].storers {
			seen[from] = st.observed
		}
		b.mu.Unlock()
		try := func(srv *Node, id byte) netip.Addr {
			to := s.socket().Addr()
			p := &wire.Punch{Topic: topic, Target: b.key, Key: [32]byte{id}, Addr: to, Class: wire.ClassConsistent, PunchID: [8]byte{id}}
			s.net.Inject(addrOf(srv), seen[addrOf(srv)], storerPunch(t, srv, b, topic, uint64(id), p))
			return to.Addr()
		}
		b.mu.Lock()
		b.pending = append(b.pending, netip.MustParseAddr("203.0.113.1")) // one connection held already
		b.mu.Unlock()
		first := try(srvs[0], 1)
		if _, ok := waitFor(t, 500*time.Millisecond, func() bool { return b.budget.Active() == 1 }); !ok {
			t.Fatal("the first birthday punch did not start")
		}
		b.mu.Lock()
		reserved := slices.Contains(b.pending, first)
		b.mu.Unlock()
		if !reserved {
			t.Fatal("the running punch reserved no place for its requester IP")
		}
		try(srvs[1], 2)
		if _, ok := waitFor(t, 500*time.Millisecond, func() bool { return b.budget.Active() == 2 }); ok {
			t.Fatal("a second birthday punch started though only one place was left")
		}
		b.mu.Lock()
		b.pending = slices.DeleteFunc(b.pending, func(ip netip.Addr) bool { return ip == netip.MustParseAddr("203.0.113.1") })
		b.mu.Unlock()
	})
}

// A birthday punch that ends releases its own reservation, not another running punch's.
func TestPendingReleasesOwn(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := fastConfig(false)
		cfg.PunchTimeout, cfg.MaxRandomPunches, cfg.MaxRandomPunchesPerMinute = 10*time.Second, 2, 64
		cfg.MaxPunchSockets = 2 * punch.Sockets
		s, _, srvs, b, topic := announced(t, 57, 2, cfg)
		forceRandom(b)
		b.mu.Lock()
		seen := map[netip.AddrPort]netip.AddrPort{}
		for from, st := range b.announces[topic].storers {
			seen[from] = st.observed
		}
		b.mu.Unlock()
		a1, a2 := s.socket(), s.socket()
		try := func(srv *Node, id byte, to netip.AddrPort) {
			p := &wire.Punch{Topic: topic, Target: b.key, Key: [32]byte{id}, Addr: to, Class: wire.ClassConsistent, PunchID: [8]byte{id}}
			s.net.Inject(addrOf(srv), seen[addrOf(srv)], storerPunch(t, srv, b, topic, uint64(id), p))
		}
		// Set before any punch runs: the first punch's sockets open, the second punch's fail.
		var opened atomic.Int32
		listen := b.listen
		b.listen = func() (net.PacketConn, error) {
			if opened.Add(1) > punch.Sockets-1 {
				return nil, errors.New("no socket")
			}
			return listen()
		}
		try(srvs[0], 1, a1.Addr())
		if _, ok := waitFor(t, 500*time.Millisecond, func() bool { return b.budget.Active() == 1 }); !ok {
			t.Fatal("the first punch did not start")
		}
		if _, ok := waitFor(t, 2*time.Second, func() bool { return opened.Load() >= punch.Sockets-1 }); !ok {
			t.Fatal("the first punch did not open its sockets")
		}
		try(srvs[1], 2, a2.Addr())
		// The second punch has run once its socket failed to open and it is gone from punching.
		var got []netip.Addr
		_, ok := waitFor(t, 2*time.Second, func() bool {
			b.mu.Lock()
			defer b.mu.Unlock()
			got = slices.Clone(b.pending)
			return opened.Load() > punch.Sockets-1 && b.punching == 1
		})
		if !ok || len(got) != 1 || got[0] != a1.Addr().Addr() {
			t.Fatalf("pending %v after the second punch failed, want only the running punch's %v", got, a1.Addr().Addr())
		}
	})
}

// A consistent announcer ignores the held table: its punches open no birthday socket and reserve nothing.
func TestConsistentPunchIgnoresHeld(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		s, tp, srvs, b, topic := announced(t, 58, 1, fastConfig(false))
		victim := s.socket()
		b.mu.Lock()
		for range b.cfg.MaxPunches {
			b.pending = append(b.pending, victim.Addr().Addr())
		}
		b.mu.Unlock()
		p := &wire.Punch{Topic: topic, Target: b.key, Key: [32]byte{7}, Addr: victim.Addr(), Class: wire.ClassConsistent, PunchID: [8]byte{1}}
		s.net.Inject(addrOf(srvs[0]), storerView(b, topic), storerPunch(t, srvs[0], b, topic, 1, p))
		if _, ok := waitFor(t, time.Second, func() bool { return sentTo(tp, 0, victim.Addr().Addr()) > 0 }); !ok {
			t.Fatal("a consistent punch was refused because the held table is full")
		}
		if _, ok := waitFor(t, 30*time.Second, func() bool { b.mu.Lock(); defer b.mu.Unlock(); return b.punching == 0 }); !ok {
			t.Fatal("the consistent punch did not end")
		}
		b.mu.Lock()
		n := len(b.pending)
		b.pending = nil
		b.mu.Unlock()
		if n != b.cfg.MaxPunches {
			t.Fatalf("a consistent punch reserved a place: pending %d", n)
		}
	})
}

// A punch that ends drops one reservation of its requester IP: not the first or last entry, not every entry.
func TestUnreserve(t *testing.T) {
	a, b := netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("198.51.100.2")
	n := &Node{pending: []netip.Addr{a, b, a}}
	n.unreserve(b)
	if !slices.Equal(n.pending, []netip.Addr{a, a}) {
		t.Fatalf("pending %v after releasing b", n.pending)
	}
	n.unreserve(a)
	n.unreserve(netip.MustParseAddr("203.0.113.1"))
	if !slices.Equal(n.pending, []netip.Addr{a}) {
		t.Fatalf("pending %v after releasing one a", n.pending)
	}
}

// A random announcer answers a PUNCH before it opens its birthday sockets: a slow open must not make the relay, which
// waits only RequestTimeout, give up while the announcer punches on and turns other relays away.
func TestSlowBirthdayOpen(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		ctx := testCtx(t, 30*time.Second)
		s := newSim(t, netsim.Config{Seed: 1})
		servers := []*Node{s.server(), s.server(), s.server()}
		bootstrap(t, ctx, servers[1:], servers[0])
		a, b := s.peer(natKinds[2], fastConfig(false)), s.peer(symmetric, fastConfig(false))
		bootstrap(t, ctx, servers, a, b)
		listen := b.listen
		b.listen = func() (net.PacketConn, error) { // set before any punch; 255 opens take longer than RequestTimeout
			time.Sleep(2 * time.Millisecond)
			return listen()
		}
		if err := connectPair(t, ctx, a, b, topicOf("slow")); err != nil {
			t.Fatalf("Connect to an announcer that opens its sockets slowly: %v", err)
		}
	})
}

// A random announcer whose birthday sockets fail to open answers try later: the connector spends no window or cooldown.
func TestBirthdayOpenFailsTryLater(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		ctx := testCtx(t, 30*time.Second)
		s := newSim(t, netsim.Config{Seed: 1})
		servers := []*Node{s.server(), s.server(), s.server()}
		bootstrap(t, ctx, servers[1:], servers[0])
		a, b := s.peer(natKinds[2], fastConfig(false)), s.peer(symmetric, fastConfig(false))
		bootstrap(t, ctx, servers, a, b)
		b.listen = func() (net.PacketConn, error) { return nil, errors.New("no socket") } // set before any punch
		if err := b.Announce(ctx, topicOf("nofd")); err != nil {
			t.Fatal(err)
		}
		recs, err := a.Lookup(ctx, topicOf("nofd"))
		if err != nil || len(recs) != 1 {
			t.Fatalf("Lookup: %v, %v", recs, err)
		}
		start := time.Now()
		if _, err := a.Connect(ctx, recs[0]); !errors.Is(err, ErrTryLater) {
			t.Fatalf("Connect: %v, want ErrTryLater", err)
		}
		if d := time.Since(start); d > time.Second {
			t.Fatalf("ErrTryLater after %v, want before any window", d)
		}
		if a.budget.Refused(recs[0].relays[0].addr.Addr(), time.Now()) {
			t.Fatal("the connector is in a cooldown for a punch that never ran")
		}
	})
}
