package kolodht

// Tests for two peers that connect to each other at once (simultaneous open), over internal/netsim. Simulation only.

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/ciranda-dev/kolo-dht/internal/netsim"
	"github.com/ciranda-dev/kolo-dht/internal/punch"
	"github.com/ciranda-dev/kolo-dht/internal/wire"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

// filterConn is a peer socket that loses the datagrams drop matches, while drop is set.
type filterConn struct {
	*netsim.Conn
	drop atomic.Pointer[func([]byte) bool]
}

func (c *filterConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		k, from, err := c.Conn.ReadFrom(b)
		if f := c.drop.Load(); err != nil || f == nil || !(*f)(b[:k]) {
			return k, from, err
		}
	}
}

func (c *filterConn) set(f func([]byte) bool) {
	if f == nil {
		c.drop.Store(nil)
		return
	}
	c.drop.Store(&f)
}

// echoes matches a probe that echoes a nonce: a node that gets none proves no address, so it never dials.
func echoes(b []byte) bool {
	_, m, err := wire.Decode(b)
	p, ok := m.(*wire.Probe)
	return err == nil && ok && p.Echo != [wire.PunchIDSize]byte{}
}

// isQUIC matches every datagram that is not the DHT's, so a dial to the node fails.
func isQUIC(b []byte) bool { return len(b) > 0 && b[0] != wire.Marker }

// crossConfig is fastConfig with the default PunchTimeout, which a punch session left open would hold.
func crossConfig() *Config {
	c := fastConfig(false)
	c.PunchTimeout = 45 * time.Second
	return c
}

// crossing is peers that announce one topic, with one server for all or, spread, one server per peer after the
// first, which uses them all. The peers probe at the production interval, so a punch window outlasts a failed dial.
type crossing struct {
	t       *testing.T
	ctx     context.Context
	net     *netsim.Network
	servers []*Node
	peers   []*Node
	conns   []*filterConn
	topic   Topic
}

func newCrossing(t *testing.T, seed uint64, spread bool, cfgs ...*Config) *crossing {
	t.Helper()
	x := &crossing{t: t, ctx: testCtx(t, 5*time.Minute), topic: topicOf("crossed")}
	s := newSim(t, netsim.Config{Seed: seed})
	servers := []*Node{s.server()}
	for spread && len(servers) < len(cfgs)-1 {
		servers = append(servers, s.server())
	}
	x.net, x.servers = s.net, servers
	for i, cfg := range cfgs {
		h, err := s.net.AddHost(s.ip(19))
		if err != nil {
			t.Fatal(err)
		}
		pc, err := h.ListenUDP(5000)
		if err != nil {
			t.Fatal(err)
		}
		fc := &filterConn{Conn: pc}
		tm := simTiming
		tm.randomPort = aim(s.net, h)
		tm.consistentEvery = punch.ConsistentEvery
		n, err := newConn(context.Background(), fc, func() (net.PacketConn, error) { return h.ListenUDP(0) }, ident(t), cfg, tm, -1)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { n.Close() })
		boot := servers
		if spread && i > 0 {
			boot = servers[i-1 : i]
		}
		bootstrap(t, x.ctx, boot, n)
		if err := n.Announce(x.ctx, x.topic); err != nil {
			t.Fatal(err)
		}
		x.peers, x.conns = append(x.peers, n), append(x.conns, fc)
	}
	return x
}

// record is to's record as from looks it up.
func (x *crossing) record(from, to *Node) Record {
	x.t.Helper()
	recs, err := from.Lookup(x.ctx, x.topic)
	if err != nil {
		x.t.Fatal(err)
	}
	for _, r := range recs {
		if bytes.Equal(r.PublicKey, to.id.PublicKey()) {
			return r
		}
	}
	x.t.Fatal("no record of the peer")
	return Record{}
}

type connected struct {
	c   *kolosecure.Conn
	err error
}

// connect runs n.Connect(r) and sends its result.
func connect(ctx context.Context, n *Node, r Record) <-chan connected {
	done := make(chan connected, 1)
	go func() {
		c, err := n.Connect(ctx, r)
		done <- connected{c, err}
	}()
	return done
}

func sessionCount(n *Node) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.sessions)
}

// wantClean fails the test if n holds a punch session, a punch waiting for a connection, or a claim.
func wantClean(t *testing.T, name string, n *Node) {
	t.Helper()
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.sessions)+len(n.sessionHosts)+len(n.watchers)+len(n.claims)+n.punching != 0 {
		t.Errorf("%s holds %d punch sessions (%d hosts), %d waits, %d claims, %d punches", name, len(n.sessions), len(n.sessionHosts), len(n.watchers), len(n.claims), n.punching)
	}
}

// waitSessions waits until n holds want punch sessions.
func (x *crossing) waitSessions(n *Node, want int) {
	x.t.Helper()
	if _, ok := waitFor(x.t, 5*time.Second, func() bool { return sessionCount(n) == want }); !ok {
		x.t.Fatalf("%d punch sessions, want %d", sessionCount(n), want)
	}
}

// wantPair fails the test unless ca, from a, and cb, from b, are the two ends of one link.
func (x *crossing) wantPair(a, b *Node, ca, cb *kolosecure.Conn) {
	x.t.Helper()
	if !bytes.Equal(ca.RemotePublicKey(), b.id.PublicKey()) || !bytes.Equal(cb.RemotePublicKey(), a.id.PublicKey()) {
		x.t.Fatal("a connection reached another key")
	}
	echo(x.t, x.ctx, ca, cb)
}

// cross runs b's Connect to a, waits until a answers its punch, then runs a's Connect to b. b's filter keeps it from
// dialing, so a dials and b's Connect takes a's connection by its claim.
func (x *crossing) cross(a, b *Node, ra, rb Record) {
	x.t.Helper()
	before := sessionCount(a)
	done := connect(x.ctx, b, ra)
	x.waitSessions(a, before+1)
	ca, err := a.Connect(x.ctx, rb)
	if err != nil {
		x.t.Fatalf("a's Connect: %v", err)
	}
	defer ca.Close()
	r := <-done
	if r.err != nil {
		x.t.Fatalf("b's Connect: %v", r.err)
	}
	defer r.c.Close()
	x.wantPair(a, b, ca, r.c)
}

// TestCrossedConnectEndsPunch: b's Connect takes a's connection by its claim and never dials; a's punch session for b
// ends with that dial instead of holding a place for PunchTimeout.
func TestCrossedConnectEndsPunch(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		x := newCrossing(t, 80, false, crossConfig(), crossConfig())
		a, b := x.peers[0], x.peers[1]
		x.conns[1].set(echoes)
		x.cross(a, b, x.record(b, a), x.record(a, b))
		synctest.Wait()
		wantClean(t, "a", a)
		wantClean(t, "b", b)
	})
}

// TestRepeatedCrossedConnects crosses one pair again and again; a session left per crossing would fill a's places.
func TestRepeatedCrossedConnects(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		x := newCrossing(t, 81, false, crossConfig(), crossConfig())
		a, b := x.peers[0], x.peers[1]
		ra, rb := x.record(b, a), x.record(a, b)
		x.conns[1].set(echoes)
		for range 2 * maxDestAttempts {
			x.cross(a, b, ra, rb)
			synctest.Wait()
			wantClean(t, "a", a)
			wantClean(t, "b", b)
		}
	})
}

// TestBothSidesCross: both connect at once and dial once each answered the other's punch; no punch session, wait or
// claim outlives them.
func TestBothSidesCross(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		x := newCrossing(t, 82, false, crossConfig(), crossConfig())
		a, b := x.peers[0], x.peers[1]
		ra, rb := x.record(b, a), x.record(a, b)
		x.conns[0].set(echoes)
		x.conns[1].set(echoes)
		da, db := connect(x.ctx, a, rb), connect(x.ctx, b, ra)
		// Its own punch and the other's: neither proves an address before both are open.
		x.waitSessions(a, 2)
		x.waitSessions(b, 2)
		x.conns[0].set(nil)
		x.conns[1].set(nil)
		for i, d := range []<-chan connected{da, db} {
			r := <-d
			if r.err != nil {
				t.Fatalf("Connect %d: %v", i, r.err)
			}
			defer r.c.Close()
		}
		synctest.Wait()
		wantClean(t, "a", a)
		wantClean(t, "b", b)
	})
}

// TestCrossedDialFails: a's dial to b fails during the crossing, so the session a opened for b's CONNECT stays in use
// and b's own punch connects through it.
func TestCrossedDialFails(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		ac := crossConfig()
		ac.Secure = &kolosecure.Config{HandshakeTimeout: 2 * time.Second, Transport: &kolotransport.Config{HandshakeTimeout: time.Second}}
		x := newCrossing(t, 86, false, ac, crossConfig())
		a, b := x.peers[0], x.peers[1]
		ra, rb := x.record(b, a), x.record(a, b)
		x.conns[1].set(func(p []byte) bool { return echoes(p) || isQUIC(p) })
		done := connect(x.ctx, b, ra)
		x.waitSessions(a, 1)
		if _, err := a.Connect(x.ctx, rb); !errors.Is(err, ErrUnreachable) {
			t.Fatalf("a's Connect with its dial lost: %v, want ErrUnreachable", err)
		}
		if n := sessionCount(a); n != 1 {
			t.Fatalf("a holds %d punch sessions after its failed dial, want b's", n)
		}
		x.conns[1].set(nil)
		r := <-done
		if r.err != nil {
			t.Fatalf("b's Connect after a's failed dial: %v", r.err)
		}
		defer r.c.Close()
		ca, err := a.Accept(x.ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer ca.Close()
		x.wantPair(a, b, ca, r.c)
		synctest.Wait()
		wantClean(t, "a", a)
		wantClean(t, "b", b)
	})
}

// TestCloseDuringCrossing closes a while its dial waits for b: a's Connect returns ErrClosed, a holds nothing, and b's
// punch ends at PunchTimeout.
func TestCloseDuringCrossing(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		x := newCrossing(t, 87, false, crossConfig(), crossConfig())
		a, b := x.peers[0], x.peers[1]
		ra, rb := x.record(b, a), x.record(a, b)
		var dials atomic.Int32
		x.conns[1].set(func(p []byte) bool {
			if isQUIC(p) {
				dials.Add(1)
				return true
			}
			return echoes(p)
		})
		done := connect(x.ctx, b, ra)
		x.waitSessions(a, 1)
		da := connect(x.ctx, a, rb)
		if _, ok := waitFor(t, 5*time.Second, func() bool { return dials.Load() > 0 }); !ok {
			t.Fatal("a never dialed b")
		}
		a.Close()
		if r := <-da; !errors.Is(r.err, ErrClosed) {
			t.Fatalf("a's Connect: %v, want ErrClosed", r.err)
		}
		wantClean(t, "a", a)
		x.conns[1].set(nil)
		if r := <-done; !errors.Is(r.err, ErrUnreachable) {
			t.Fatalf("b's Connect to a closed a: %v, want ErrUnreachable", r.err)
		}
		time.Sleep(crossConfig().PunchTimeout)
		synctest.Wait()
		wantClean(t, "b", b)
	})
}

// TestManyCrossedConnects: four peers connect to a while a connects to each; every Connect returns the link and no node
// keeps a session. A server relays maxRelaysPerHost CONNECTs per host and answers the next full, so each peer has one.
func TestManyCrossedConnects(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		const peers = 4
		cfgs := []*Config{crossConfig()}
		for range peers {
			cfgs = append(cfgs, crossConfig())
		}
		x := newCrossing(t, 88, true, cfgs...)
		a := x.peers[0]
		var theirs, ours []<-chan connected
		for i, b := range x.peers[1:] {
			x.conns[i+1].set(echoes)
			theirs = append(theirs, connect(x.ctx, b, x.record(b, a)))
			x.waitSessions(a, i+1)
		}
		relays := map[netip.AddrPort]bool{}
		for _, b := range x.peers[1:] {
			r := x.record(a, b)
			if len(r.relays) != 1 || relays[r.relays[0].server] {
				t.Fatalf("a's record of a peer has relays %v, want one server of its own", r.relays)
			}
			relays[r.relays[0].server] = true
			ours = append(ours, connect(x.ctx, a, r))
		}
		for i, b := range x.peers[1:] {
			ra, rb := <-ours[i], <-theirs[i]
			if ra.err != nil || rb.err != nil {
				t.Fatalf("peer %d: a's Connect %v, its Connect %v", i, ra.err, rb.err)
			}
			defer ra.c.Close()
			defer rb.c.Close()
			x.wantPair(a, b, ra.c, rb.c)
		}
		synctest.Wait()
		for i, n := range x.peers {
			wantClean(t, string(rune('a'+i)), n)
		}
	})
}

// TestRandomAnnouncerDialEndsWaits: a random announcer's own dial ends every punch waiting for that key, as an
// accepted connection does. The extra wait stands for a second punch asked with the same key.
func TestRandomAnnouncerDialEndsWaits(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		ctx := testCtx(t, 30*time.Second)
		s := newSim(t, netsim.Config{Seed: 89})
		servers := []*Node{s.server(), s.server(), s.server()}
		bootstrap(t, ctx, servers[1:], servers[0])
		b := s.peer(natKind{"random-open", false, netsim.NATConfig{Mapping: netsim.AddressPortDependent, Filtering: netsim.EndpointIndependentFiltering}}, fastConfig(false))
		bootstrap(t, ctx, servers, b)
		topic := topicOf("dial-ends-waits")
		if err := b.Announce(ctx, topic); err != nil {
			t.Fatal(err)
		}
		bAddr := storerView(b, topic)
		b.mu.Lock()
		var srv *Node
		for from, st := range b.announces[topic].storers {
			for _, x := range servers {
				if addrOf(x) == from && st.observed == bAddr {
					srv = x
				}
			}
		}
		random := b.nat.class(time.Now()) == wire.ClassRandom
		b.mu.Unlock()
		if !random || srv == nil {
			t.Fatal("need a random announcer and its storer")
		}
		b.mu.Lock()
		w := b.watch(srv.key)
		b.mu.Unlock()
		p := &wire.Punch{Topic: topic, Target: b.key, Key: srv.key, Addr: s.socket().Addr(), Class: wire.ClassConsistent, PunchID: [8]byte{1}}
		s.net.Inject(addrOf(srv), bAddr, storerPunch(t, srv, b, topic, 1, p))
		if _, ok := waitFor(t, 500*time.Millisecond, func() bool { return b.budget.Active() == 1 }); !ok {
			t.Fatal("the burst did not start")
		}
		srv.mu.Lock()
		ss, ok := srv.openSession([8]byte{1}, bAddr)
		srv.mu.Unlock()
		if !ok {
			t.Fatal("openSession")
		}
		srv.probe(ss, bAddr)
		c, err := srv.Accept(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		srv.closeSession(ss)
		synctest.Wait()
		select {
		case ip := <-w:
			if ip != addrOf(srv).Addr() {
				t.Fatalf("the wait got %v, want %v", ip, addrOf(srv).Addr())
			}
		default:
			t.Fatal("a punch waiting for the key outlived the announcer's dial")
		}
	})
}

// TestConnectedWakesEachWaitOnce: a wait gets the first connection with its key and is then gone, so a second
// connection with that key, dialed and accepted at once, never blocks on it.
func TestConnectedWakesEachWaitOnce(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		x := newCrossing(t, 90, false, crossConfig(), crossConfig())
		a, b := x.peers[0], x.peers[1]
		c, err := a.sl.Dial(x.ctx, addrOf(b), b.key[:])
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		a.mu.Lock()
		w := a.watch(b.key)
		a.connected(c)
		a.connected(c)
		a.mu.Unlock()
		if ip := <-w; ip != addrOf(b).Addr() {
			t.Fatalf("the wait got %v, want %v", ip, addrOf(b).Addr())
		}
		wantClean(t, "a", a)
	})
}

// TestLatePunchEndsWithWindow: b's PUNCH reaches a after a's Connect dialed b, and b's Connect still takes a's
// connection by its claim. Nothing tells a that b's punch is over, so the wait ends with the two-consistent probe window.
func TestLatePunchEndsWithWindow(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		x := newCrossing(t, 91, false, crossConfig(), crossConfig())
		a, b := x.peers[0], x.peers[1]
		ra, rb := x.record(b, a), x.record(a, b)
		punches := make(chan []byte, 1)
		x.conns[0].set(func(p []byte) bool {
			_, m, err := wire.Decode(p)
			if _, ok := m.(*wire.Punch); err != nil || !ok {
				return false
			}
			select {
			case punches <- bytes.Clone(p):
			default:
			}
			return true
		})
		x.conns[1].set(echoes)
		done := connect(x.ctx, b, ra)
		p := <-punches
		ca, err := a.Connect(x.ctx, rb)
		if err != nil {
			t.Fatalf("a's Connect: %v", err)
		}
		defer ca.Close()
		x.conns[0].set(nil)
		x.net.Inject(addrOf(x.servers[0]), addrOf(a), p)
		r := <-done
		if r.err != nil {
			t.Fatalf("b's Connect: %v", r.err)
		}
		defer r.c.Close()
		x.wantPair(a, b, ca, r.c)
		synctest.Wait()
		if n := sessionCount(a); n != 1 {
			t.Fatalf("a holds %d punch sessions, want the late one", n)
		}
		time.Sleep(a.consistentWindow())
		synctest.Wait()
		wantClean(t, "a", a)
		wantClean(t, "b", b)
	})
}

// TestRefusedPunchOpensNoSession: a node whose listener refuses the requester's address (AcceptFunc false, or a
// panic) answers its PUNCH refused, so no session waits for a connection that could never arrive.
func TestRefusedPunchOpensNoSession(t *testing.T) {
	checkGoroutines(t)
	for _, tc := range []struct {
		name   string
		accept func(netip.AddrPort) bool
		want   error
	}{
		{"refuses", func(netip.AddrPort) bool { return false }, ErrUnreachable},
		{"panics", func(netip.AddrPort) bool { panic("refused") }, ErrUnreachable},
		{"accepts", func(netip.AddrPort) bool { return true }, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				bc := crossConfig()
				bc.Secure = &kolosecure.Config{HandshakeTimeout: 2 * time.Second, Transport: &kolotransport.Config{AcceptFunc: tc.accept}}
				x := newCrossing(t, 92, false, crossConfig(), bc)
				a, b := x.peers[0], x.peers[1]
				c, err := a.Connect(x.ctx, x.record(a, b))
				if !errors.Is(err, tc.want) {
					t.Fatalf("Connect: %v, want %v", err, tc.want)
				}
				if c != nil {
					defer c.Close()
					cb, err := b.Accept(x.ctx)
					if err != nil {
						t.Fatal(err)
					}
					defer cb.Close()
					x.wantPair(a, b, c, cb)
				}
				synctest.Wait()
				wantClean(t, "a", a)
				wantClean(t, "b", b)
			})
		})
	}
}

// TestRelayFullTryLater: relays that answer full make Connect return ErrTryLater, not ErrUnreachable.
func TestRelayFullTryLater(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		ctx := testCtx(t, 20*time.Second)
		s := newSim(t, netsim.Config{Seed: 93})
		a := s.peer(natKinds[0], fastConfig(false))
		id, nobody := ident(t), s.socket()
		rec := Record{PublicKey: id.PublicKey(), Addr: nobody.Addr()}
		for range maxRelays {
			rec.relays = append(rec.relays, relay{server: fakeRelayOn(t, s.socket(), fakeAnswer{status: wire.StatusFull}), addr: nobody.Addr()})
		}
		if _, err := a.Connect(ctx, rec); !errors.Is(err, ErrTryLater) {
			t.Fatalf("Connect through full relays: %v, want ErrTryLater", err)
		}
		wantClean(t, "a", a)
	})
}

// TestRandomPunchKeepsPunchTimeout: with a random mapping on one side the random probes take most of PunchTimeout,
// so the announcer keeps waiting past the window of two consistent mappings, and ends at PunchTimeout.
func TestRandomPunchKeepsPunchTimeout(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		ctx := testCtx(t, time.Minute)
		s := newSim(t, netsim.Config{Seed: 94})
		srv := s.server()
		cfg := crossConfig()
		b := s.peer(natKinds[0], cfg)
		bootstrap(t, ctx, []*Node{srv}, b)
		topic := topicOf("random-waits")
		if err := b.Announce(ctx, topic); err != nil {
			t.Fatal(err)
		}
		p := &wire.Punch{Topic: topic, Target: b.key, Key: [32]byte{7}, Addr: s.socket().Addr(), Class: wire.ClassRandom, PunchID: [8]byte{1}}
		s.net.Inject(addrOf(srv), storerView(b, topic), storerPunch(t, srv, b, topic, 9, p))
		if _, ok := waitFor(t, time.Second, func() bool { return sessionCount(b) == 1 }); !ok {
			t.Fatal("the punch did not start")
		}
		opened := time.Now()
		time.Sleep(2 * b.consistentWindow())
		if n := sessionCount(b); n != 1 {
			t.Fatalf("%d punch sessions %v after the punch started, want 1 until PunchTimeout", n, time.Since(opened))
		}
		time.Sleep(cfg.PunchTimeout)
		synctest.Wait()
		wantClean(t, "b", b)
	})
}
