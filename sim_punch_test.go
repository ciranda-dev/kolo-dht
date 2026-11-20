package kolodht

// Random-mapping punch tests over internal/netsim. Simulation only.

import (
	"errors"
	"net/netip"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/ciranda-dev/kolo-dht/internal/netsim"
	"github.com/ciranda-dev/kolo-dht/internal/punch"
	"github.com/ciranda-dev/kolo-dht/internal/wire"
	koloid "github.com/ciranda-dev/kolo-id"
)

// probeSize is the length of a PROBE datagram.
const probeSize = 35

var (
	portRestricted = natKinds[3]
	symmetric      = natKinds[4]
)

type tap struct {
	mu   sync.Mutex
	pkts []netsim.Packet
}

func (t *tap) add(p netsim.Packet) {
	t.mu.Lock()
	t.pkts = append(t.pkts, p)
	t.mu.Unlock()
}

func (t *tap) all() []netsim.Packet {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]netsim.Packet(nil), t.pkts...)
}

// pairSim starts three servers and two peers of the given kinds, bootstrapped.
func pairSim(t *testing.T, seed uint64, tp *tap, ka, kb natKind, ca, cb *Config) (*sim, *Node, *Node) {
	cfg := netsim.Config{Seed: seed}
	if tp != nil {
		cfg.Tap = tp.add
	}
	ctx := testCtx(t, 10*time.Second)
	s := newSim(t, cfg)
	servers := []*Node{s.server(), s.server(), s.server()}
	bootstrap(t, ctx, servers[1:], servers[0])
	a, b := s.peer(ka, ca), s.peer(kb, cb)
	bootstrap(t, ctx, servers, a, b)
	return s, a, b
}

// observedAddr is n's address as the servers see it.
func observedAddr(t *testing.T, n *Node) netip.AddrPort {
	t.Helper()
	_, maj, _ := classOf(n)
	if !maj.IsValid() {
		t.Fatal("no majority address")
	}
	return maj
}

// TestSimBirthdayPackets connects a port-restricted peer to a symmetric one and checks every punch packet: the birthday
// side sends TTL 5 from 255 new sockets to the peer's verified address; the other side's random probes go only to its IP.
func TestSimBirthdayPackets(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		ctx := testCtx(t, 30*time.Second)
		tp := &tap{}
		_, a, b := pairSim(t, 7, tp, portRestricted, symmetric, fastConfig(false), fastConfig(false))
		aAddr := observedAddr(t, a)
		b.mu.Lock()
		bIP, _ := b.nat.publicIP()
		b.mu.Unlock()
		start := len(tp.all())
		if err := connectPair(t, ctx, a, b, topicOf("birthday")); err != nil {
			t.Fatal(err)
		}
		low := map[netip.AddrPort]bool{}
		probes := 0
		for _, p := range tp.all()[start:] {
			if p.TTL == punch.LowTTL {
				if p.To != aAddr {
					t.Fatalf("TTL 5 packet to %v, want only %v", p.To, aAddr)
				}
				low[p.From] = true
			}
			if p.To.Addr() == bIP && p.Size == probeSize {
				if p.To.Port() < punch.MinRandomPort {
					t.Fatalf("probe to port %d", p.To.Port())
				}
				probes++
			}
		}
		if len(low) != punch.Sockets-1 {
			t.Fatalf("TTL 5 packets from %d sockets, want %d", len(low), punch.Sockets-1)
		}
		if probes == 0 || probes > punch.RandomTries+punch.ConsistentTries {
			t.Fatalf("%d probes to the birthday side", probes)
		}
		t.Logf("%d probes to the birthday side", probes)
		// The winning socket closes with its connection; the others closed at the commit.
		_, ok := waitFor(t, 5*time.Second, func() bool { return b.budget.Sockets() == 0 && b.budget.Active() == 0 })
		if !ok {
			t.Fatalf("birthday side holds %d sockets, %d punches", b.budget.Sockets(), b.budget.Active())
		}
	})
}

// TestSimBirthdayConnector is the other direction: the connector has the random mapping and dials from its winning
// socket; the connection ends with the extra listener.
func TestSimBirthdayConnector(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		ctx := testCtx(t, 30*time.Second)
		_, a, b := pairSim(t, 8, nil, symmetric, portRestricted, fastConfig(false), fastConfig(false))
		if err := connectPair(t, ctx, a, b, topicOf("birthday")); err != nil {
			t.Fatal(err)
		}
		_, ok := waitFor(t, 5*time.Second, func() bool { return a.budget.Sockets() == 0 && a.budget.Active() == 0 })
		if !ok {
			t.Fatalf("connector holds %d sockets, %d punches", a.budget.Sockets(), a.budget.Active())
		}
	})
}

// TestSimRandomPunchTryLater: a random punch inside RandomPunchInterval of the last one fails fast with ErrTryLater,
// at the connector (before any packet) and through the announcer's TryLater reply; after the interval it works.
func TestSimRandomPunchTryLater(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		ctx := testCtx(t, 60*time.Second)
		cfg := fastConfig(false)
		cfg.RandomPunchInterval = 2 * time.Second
		s, a, b := pairSim(t, 9, nil, symmetric, portRestricted, cfg, fastConfig(false))
		if err := connectPair(t, ctx, a, b, topicOf("first")); err != nil {
			t.Fatal(err)
		}
		c := s.peer(portRestricted, fastConfig(false))
		if err := c.Bootstrap(ctx, a.boot); err != nil {
			t.Fatal(err)
		}
		topic := topicOf("second")
		if err := c.Announce(ctx, topic); err != nil {
			t.Fatal(err)
		}
		recs, err := a.Lookup(ctx, topic)
		if err != nil || len(recs) != 1 {
			t.Fatalf("Lookup: %v, %v", recs, err)
		}
		began := time.Now()
		if _, err := a.Connect(ctx, recs[0]); !errors.Is(err, ErrTryLater) {
			t.Fatalf("connector inside the interval: %v, want ErrTryLater", err)
		}
		if d := time.Since(began); d > 100*time.Millisecond {
			t.Fatalf("ErrTryLater after %v, want at once", d)
		}
		time.Sleep(2 * time.Second)
		conn, err := a.Connect(ctx, recs[0])
		if err != nil {
			t.Fatalf("after the interval: %v", err)
		}
		conn.Close()

		// The announcer refuses a second random punch within its own interval.
		bcfg := fastConfig(false)
		bcfg.RandomPunchInterval = time.Minute
		s2, x, y := pairSim(t, 10, nil, portRestricted, symmetric, fastConfig(false), bcfg)
		if err := connectPair(t, ctx, x, y, topicOf("first")); err != nil {
			t.Fatal(err)
		}
		z := s2.peer(portRestricted, fastConfig(false))
		if err := z.Bootstrap(ctx, x.boot); err != nil {
			t.Fatal(err)
		}
		recs, err = z.Lookup(ctx, topicOf("first"))
		if err != nil || len(recs) != 1 {
			t.Fatalf("Lookup: %v, %v", recs, err)
		}
		if _, err := z.Connect(ctx, recs[0]); !errors.Is(err, ErrTryLater) {
			t.Fatalf("announcer inside the interval: %v, want ErrTryLater", err)
		}
	})
}

// TestSimPunchSocketBudget: a birthday punch needs 255 sockets; with fewer it is ErrTryLater on both sides.
func TestSimPunchSocketBudget(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		ctx := testCtx(t, 30*time.Second)
		small := fastConfig(false)
		small.MaxPunchSockets = punch.Sockets - 2
		_, a, b := pairSim(t, 11, nil, symmetric, portRestricted, small, fastConfig(false))
		if err := b.Announce(ctx, topicOf("budget")); err != nil {
			t.Fatal(err)
		}
		recs, err := a.Lookup(ctx, topicOf("budget"))
		if err != nil || len(recs) != 1 {
			t.Fatalf("Lookup: %v, %v", recs, err)
		}
		if _, err := a.Connect(ctx, recs[0]); !errors.Is(err, ErrTryLater) {
			t.Fatalf("connector: %v, want ErrTryLater", err)
		}
		_, x, y := pairSim(t, 12, nil, portRestricted, symmetric, fastConfig(false), small)
		if err := connectPair(t, ctx, x, y, topicOf("budget")); !errors.Is(err, ErrTryLater) {
			t.Fatalf("announcer: %v, want ErrTryLater", err)
		}
	})
}

// TestSimPunchCloseMidway closes nodes during a birthday punch: Connect returns ErrClosed at once, nothing is left open.
func TestSimPunchCloseMidway(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		ctx := testCtx(t, 30*time.Second)
		_, a, b := pairSim(t, 13, nil, symmetric, portRestricted, fastConfig(false), fastConfig(false))
		if err := b.Announce(ctx, topicOf("close")); err != nil {
			t.Fatal(err)
		}
		recs, err := a.Lookup(ctx, topicOf("close"))
		if err != nil || len(recs) != 1 {
			t.Fatalf("Lookup: %v, %v", recs, err)
		}
		// With the announcer gone, the CONNECT waits for its relay's timeout while our birthday sockets are open.
		b.Close()
		done := make(chan error, 1)
		go func() {
			_, err := a.Connect(ctx, recs[0])
			done <- err
		}()
		if _, ok := waitFor(t, 2*time.Second, func() bool { return a.budget.Sockets() == punch.Sockets-1 }); !ok {
			t.Fatalf("birthday sockets not open: %d", a.budget.Sockets())
		}
		a.Close()
		select {
		case err := <-done:
			if !errors.Is(err, ErrClosed) {
				t.Fatalf("Connect: %v, want ErrClosed", err)
			}
		case <-time.After(time.Second):
			t.Fatal("Connect still running a second after Close")
		}
		if a.budget.Sockets() != 0 || a.budget.Active() != 0 {
			t.Fatalf("after Close: %d sockets, %d punches", a.budget.Sockets(), a.budget.Active())
		}
	})
}

// TestSimAnnouncerCloseMidway closes an announcer running a birthday punch toward a requester that never answers.
func TestSimAnnouncerCloseMidway(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		ctx := testCtx(t, 20*time.Second)
		s := newSim(t, netsim.Config{Seed: 14})
		srv := s.server()
		b := s.peer(natKinds[1], fastConfig(false))
		bootstrap(t, ctx, []*Node{srv}, b)
		topic := topicOf("close")
		if err := b.Announce(ctx, topic); err != nil {
			t.Fatal(err)
		}
		forceRandom(b)
		nobody := s.socket()
		p := &wire.Punch{Topic: topic, Target: b.key, Key: [32]byte{7}, Addr: nobody.Addr(), Class: wire.ClassConsistent, PunchID: [8]byte{1}}
		s.net.Inject(addrOf(srv), storerView(b, topic), storerPunch(t, srv, b, topic, 9, p))
		if _, ok := waitFor(t, 2*time.Second, func() bool { return b.budget.Sockets() == punch.Sockets-1 }); !ok {
			t.Fatalf("birthday sockets not open: %d", b.budget.Sockets())
		}
		b.Close()
		if b.budget.Sockets() != 0 || b.budget.Active() != 0 {
			t.Fatalf("after Close: %d sockets, %d punches", b.budget.Sockets(), b.budget.Active())
		}
	})
}

// storerPunch encodes p as srv, a storer of b's record, relays it: with srv's next counter and the record's punch MAC.
func storerPunch(t *testing.T, srv, b *Node, topic Topic, id uint64, p *wire.Punch) []byte {
	t.Helper()
	srv.mu.Lock()
	rec, ok := srv.store.Find([32]byte(topic), b.key, time.Now())
	srv.mu.Unlock()
	if !ok {
		t.Fatal("storer has no record")
	}
	p.Counter = srv.punchSeq.Add(1)
	if p.MAC, ok = punchMAC(rec.Secret, p); !ok {
		t.Fatal("punchMAC")
	}
	return encode(t, id, p, 0)
}

// storerView is b's address as the storer of topic sees it.
func storerView(b *Node, topic Topic) netip.AddrPort {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, st := range b.announces[topic].storers {
		return st.observed
	}
	return netip.AddrPort{}
}

// TestPunchRandomVictim: a storer that names a victim as a random requester gets the victim at most one window of
// random probes, all probe-sized and only to the victim's IP; a second PUNCH inside the interval adds nothing.
func TestPunchRandomVictim(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		ctx := testCtx(t, 20*time.Second)
		tp := &tap{}
		s := newSim(t, netsim.Config{Seed: 15, Tap: tp.add})
		srv := s.server()
		b := s.peer(natKinds[1], fastConfig(false))
		bootstrap(t, ctx, []*Node{srv}, b)
		topic := topicOf("victim")
		if err := b.Announce(ctx, topic); err != nil {
			t.Fatal(err)
		}
		victim := s.socket()
		bAddr := storerView(b, topic)
		for i := range 2 {
			p := &wire.Punch{Topic: topic, Target: b.key, Key: [32]byte{7}, Addr: victim.Addr(), Class: wire.ClassRandom, PunchID: [8]byte{byte(i + 1)}}
			s.net.Inject(addrOf(srv), bAddr, storerPunch(t, srv, b, topic, uint64(9+i), p))
		}
		time.Sleep(time.Duration(punch.RandomTries)*simTiming.randomEvery + time.Second)
		n := 0
		for _, p := range tp.all() {
			if p.To.Addr() != victim.Addr().Addr() {
				continue
			}
			if p.Size != probeSize {
				t.Fatalf("victim got %d bytes", p.Size)
			}
			n++
		}
		if n == 0 || n > punch.RandomTries {
			t.Fatalf("victim got %d probes, want 1 to %d", n, punch.RandomTries)
		}
		t.Logf("victim got %d probes", n)
	})
}

// fakeRelayWith answers every CONNECT with status and class, unsigned, and nothing else.
func fakeRelayWith(t *testing.T, s *sim, status wire.Status, class wire.Class) netip.AddrPort {
	return fakeRelayOn(t, s.socket(), fakeAnswer{status: status, class: class})
}

// fakeAnswer is what a fake relay says to every CONNECT. An OK to a key in ids is signed as the peer at ip would sign it
// (an attacker who owns the record's key); stale signs another punch id, signed another class.
type fakeAnswer struct {
	status wire.Status
	class  wire.Class
	ip     netip.Addr
	ids    []*koloid.Identity
	stale  bool
	signed wire.Class
}

// fakeRelayOn answers every CONNECT that reaches fake with a, and nothing else.
func fakeRelayOn(t *testing.T, fake *netsim.Conn, a fakeAnswer) netip.AddrPort {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 2048)
		for {
			k, from, err := fake.ReadFrom(buf)
			if err != nil {
				return
			}
			id, m, err := wire.Decode(buf[:k])
			c, ok := m.(*wire.Connect)
			if err != nil || !ok {
				continue
			}
			reply := &wire.ConnectReply{Observed: udpAddrPort(from), Status: a.status, Class: a.class}
			for _, x := range a.ids {
				if a.status == wire.StatusOK && samePublicKey(x.PublicKey(), c.Target) {
					pid := c.PunchID
					if a.stale {
						pid[0]++
					}
					class := a.class
					if a.signed != wire.ClassUnknown {
						class = a.signed
					}
					sig, err := x.Sign(punchReplyContext, replySignable(pid, class, a.ip))
					if err != nil {
						panic(err)
					}
					reply.Sig = [wire.SigSize]byte(sig)
				}
			}
			if b, err := wire.Fit(id, reply, k); err == nil {
				fake.WriteTo(b, from)
			}
		}
	}()
	t.Cleanup(func() {
		fake.Close()
		wg.Wait()
	})
	return fake.Addr()
}

// TestSimConnectCloseAfterOK closes a node while its Connect runs a birthday punch after the peer agreed: Close
// does not wait for PunchTimeout, and Connect returns ErrClosed.
func TestSimConnectCloseAfterOK(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		ctx := testCtx(t, 20*time.Second)
		s := newSim(t, netsim.Config{Seed: 16})
		cfg := fastConfig(false)
		cfg.PunchTimeout = 10 * time.Second
		a := s.peer(natKinds[0], cfg)
		forceRandom(a)
		id, nobody := ident(t), s.socket()
		relayAddr := fakeRelayOn(t, s.socket(), fakeAnswer{status: wire.StatusOK, class: wire.ClassConsistent, ip: nobody.Addr().Addr(), ids: []*koloid.Identity{id}})
		rec := Record{PublicKey: id.PublicKey(), Addr: nobody.Addr(), relays: []relay{{server: relayAddr, addr: nobody.Addr()}}}
		done := make(chan error, 1)
		go func() {
			_, err := a.Connect(ctx, rec)
			done <- err
		}()
		if _, ok := waitFor(t, 2*time.Second, func() bool { return a.budget.Sockets() == punch.Sockets-1 }); !ok {
			t.Fatalf("birthday sockets not open: %d", a.budget.Sockets())
		}
		time.Sleep(200 * time.Millisecond)
		began := time.Now()
		a.Close()
		if d := time.Since(began); d > time.Second {
			t.Fatalf("Close took %v", d)
		}
		if err := <-done; !errors.Is(err, ErrClosed) {
			t.Fatalf("Connect: %v, want ErrClosed", err)
		}
		if a.budget.Sockets() != 0 || a.budget.Active() != 0 {
			t.Fatalf("after Close: %d sockets, %d punches", a.budget.Sockets(), a.budget.Active())
		}
	})
}
