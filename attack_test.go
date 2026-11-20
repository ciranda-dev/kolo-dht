package kolodht

// Tests for hostile inputs and abusive peers. Those that use internal/netsim are simulation only.

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/ciranda-dev/kolo-dht/internal/netsim"
	"github.com/ciranda-dev/kolo-dht/internal/punch"
	"github.com/ciranda-dev/kolo-dht/internal/records"
	"github.com/ciranda-dev/kolo-dht/internal/wire"
	koloid "github.com/ciranda-dev/kolo-id"
)

// simSocket opens a plain socket on a new public host of the simulated network.
func (s *sim) socket() *netsim.Conn {
	s.t.Helper()
	h, err := s.net.AddHost(s.ip(20))
	if err != nil {
		s.t.Fatal(err)
	}
	pc, err := h.ListenUDP(6000)
	if err != nil {
		s.t.Fatal(err)
	}
	s.t.Cleanup(func() { pc.Close() })
	return pc
}

// drain reads everything pc receives for d and returns the datagrams.
func drain(pc *netsim.Conn, d time.Duration) [][]byte {
	var out [][]byte
	deadline := time.Now().Add(d)
	buf := make([]byte, 2048)
	for {
		pc.SetReadDeadline(deadline)
		k, _, err := pc.ReadFrom(buf)
		if err != nil {
			return out
		}
		out = append(out, append([]byte(nil), buf[:k]...))
	}
}

func encode(t *testing.T, id uint64, m wire.Message, size int) []byte {
	t.Helper()
	b, err := wire.Encode(id, m, size)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func forceRandom(n *Node) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.nat = newNAT(n.tm.sampleAge)
	for i := range 4 {
		n.nat.add(netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 18, byte(100 + i), 1}), 4000), netip.AddrPortFrom(netip.MustParseAddr("198.19.9.9"), uint16(7000+i)), time.Now())
	}
}

// A storer naming a victim in a PUNCH gets at most one small datagram sent there, and never a QUIC packet.
func TestPunchVictim(t *testing.T) {
	checkGoroutines(t)
	for _, random := range []bool{false, true} {
		t.Run(map[bool]string{false: "probe", true: "dial"}[random], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx := testCtx(t, 20*time.Second)
				s := newSim(t, netsim.Config{Seed: 11})
				srv := s.server()
				b := s.peer(natKinds[1], fastConfig(false))
				bootstrap(t, ctx, []*Node{srv}, b)
				topic := topicOf("victim")
				if err := b.Announce(ctx, topic); err != nil {
					t.Fatal(err)
				}
				if random {
					forceRandom(b)
				}
				victim := s.socket()
				p := &wire.Punch{Topic: topic, Target: b.key, Key: [32]byte{7}, Addr: victim.Addr(), Class: wire.ClassConsistent, PunchID: [8]byte{1}}
				pb := storerPunch(t, srv, b, topic, 9, p)
				b.mu.Lock()
				var bAddr netip.AddrPort
				for _, st := range b.announces[topic].storers {
					bAddr = st.observed
				}
				b.mu.Unlock()
				s.net.Inject(addrOf(srv), bAddr, pb)
				// An accomplice that knows the punch id proves its own address; the victim still gets nothing more.
				acc := s.socket()
				acc.WriteTo(encode(t, 0, &wire.Probe{PunchID: p.PunchID, Nonce: [8]byte{5}}, 0), udp(bAddr))
				for _, d := range drain(acc, 200*time.Millisecond) {
					if _, m, err := wire.Decode(d); err == nil {
						if pr, ok := m.(*wire.Probe); ok && pr.Echo == [8]byte{5} {
							acc.WriteTo(encode(t, 0, &wire.Probe{PunchID: p.PunchID, Nonce: [8]byte{5}, Echo: pr.Nonce}, 0), udp(bAddr))
						}
					}
				}
				got := drain(victim, 2*time.Second)
				if len(got) > 1 {
					t.Fatalf("victim got %d datagrams", len(got))
				}
				for _, d := range got {
					if len(d) > len(pb) || d[0]&0xC0 != 0 {
						t.Fatalf("victim got %d bytes, first byte %#x, for a PUNCH of %d", len(d), d[0], len(pb))
					}
				}
			})
		})
	}
}

// A small request with the server flag gets nothing larger than itself back, ping-back included.
func TestConsiderAmplification(t *testing.T) {
	checkGoroutines(t)
	s := loopNode(t, fastConfig(true))
	r := newRaw(t)
	for _, size := range []int{0, 40, 96} {
		n := r.send(addrOf(s), 1, &wire.Ping{Flags: wire.NewFlags(2, true)}, size)
		total := 0
		for {
			b, _ := r.recv(wait)
			if b == nil {
				break
			}
			total += len(b)
		}
		if total > n {
			t.Fatalf("PING of %d bytes with the server flag got %d bytes back", n, total)
		}
	}
}

// A forged request from our own IP with our r does not change r.
func TestForgedCollision(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		s := newSim(t, netsim.Config{Seed: 12})
		n := s.server()
		before := n.r.Load()
		me := addrOf(n)
		other := netip.AddrPortFrom(me.Addr(), me.Port()+1)
		for _, m := range []wire.Message{&wire.Ping{Flags: wire.NewFlags(uint8(before), true)}, &wire.FindNode{Flags: wire.NewFlags(uint8(before), true)}} {
			s.net.Inject(other, me, encode(t, 5, m, wire.MaxSize))
			s.net.Inject(me, me, encode(t, 6, m, wire.MaxSize))
		}
		time.Sleep(200 * time.Millisecond)
		if got := n.r.Load(); got != before {
			t.Fatalf("r changed from %d to %d on forged requests", before, got)
		}
	})
}

// Bootstrapping to our own address adds nothing and keeps r.
func TestBootstrapSelf(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t, 10*time.Second)
	n := loopNode(t, fastConfig(true))
	before := n.r.Load()
	if err := n.Bootstrap(ctx, []netip.AddrPort{addrOf(n)}); !errors.Is(err, ErrNoNodes) {
		t.Fatalf("Bootstrap(self) = %v, want ErrNoNodes", err)
	}
	// Our own socket reached through another address of the host is caught by the self-request check. The node
	// records the address a wildcard socket reports, without binding one (tests use 127.0.0.1 only).
	wide := loopNode(t, fastConfig(true))
	wide.mu.Lock()
	wide.local = netip.AddrPortFrom(netip.IPv4Unspecified(), addrOf(wide).Port())
	wide.selfIP = wide.local.Addr()
	wide.mu.Unlock()
	wr := wide.r.Load()
	loop := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), addrOf(wide).Port())
	if err := wide.Bootstrap(ctx, []netip.AddrPort{loop}); !errors.Is(err, ErrNoNodes) {
		t.Fatalf("Bootstrap(self via loopback) = %v, want ErrNoNodes", err)
	}
	wide.mu.Lock()
	wheld := wide.table.Len()
	wide.mu.Unlock()
	if wheld != 0 || wide.r.Load() != wr {
		t.Fatalf("via loopback: table %d, r %d -> %d", wheld, wr, wide.r.Load())
	}
	n.mu.Lock()
	held := n.table.Len()
	n.mu.Unlock()
	if held != 0 || n.r.Load() != before {
		t.Fatalf("table %d, r %d -> %d", held, before, n.r.Load())
	}
}

func TestBootstrapSelfAndOther(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t, 10*time.Second)
	n := loopNode(t, fastConfig(true))
	other := loopNode(t, fastConfig(true))
	before := n.r.Load()
	if err := n.Bootstrap(ctx, []netip.AddrPort{addrOf(n), addrOf(other)}); err != nil {
		t.Fatal(err)
	}
	n.mu.Lock()
	entries := n.table.Closest([32]byte{}, 10)
	n.mu.Unlock()
	if len(entries) != 1 || entries[0].Addr != addrOf(other) {
		t.Fatalf("table %+v, want only the other server", entries)
	}
	if n.r.Load() != before && other.r.Load() != before {
		t.Fatalf("r changed without a collision: %d -> %d", before, n.r.Load())
	}
}

// One requester flooding CONNECTs does not keep another from getting a punch through.
func TestRelayPerRequester(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		ctx := testCtx(t, 30*time.Second)
		s := newSim(t, netsim.Config{Seed: 13})
		srv := s.server()
		a, b := s.peer(natKinds[1], fastConfig(false)), s.peer(natKinds[1], fastConfig(false))
		bootstrap(t, ctx, []*Node{srv}, a, b)
		topic := topicOf("flood")
		if err := b.Announce(ctx, topic); err != nil {
			t.Fatal(err)
		}
		r := s.socket()
		r.WriteTo(encode(t, 1, &wire.Ping{}, pingSize), udp(addrOf(srv)))
		var tok [wire.TokenSize]byte
		for _, d := range drain(r, 300*time.Millisecond) {
			if _, m, err := wire.Decode(d); err == nil {
				if pr, ok := m.(*wire.PingReply); ok {
					tok = pr.Token
				}
			}
		}
		recs, err := a.Lookup(ctx, topic)
		if err != nil || len(recs) != 1 {
			t.Fatalf("Lookup: %v", err)
		}
		// 20 CONNECTs, within quic-go's 32-datagram queue for non-QUIC packets, so none of A's own are dropped there.
		// The punch sessions they open at the announcer last PunchTimeout; A connects while they hold.
		for i := range 20 {
			c := &wire.Connect{Token: tok, Topic: topic, Target: b.key, Key: [32]byte{byte(i + 1)}, PunchID: [8]byte{byte(i + 1)}}
			r.WriteTo(encode(t, uint64(100+i), c, wire.MaxSize), udp(addrOf(srv)))
		}
		time.Sleep(100 * time.Millisecond)
		c, err := a.Connect(ctx, recs[0])
		if err != nil {
			t.Fatalf("Connect during a flood from another requester: %v", err)
		}
		c.Close()
	})
}

// Records that name a victim never make Connect dial it, and attempts to one host are bounded.
func TestSybilRecordsVictim(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		ctx := testCtx(t, 30*time.Second)
		s := newSim(t, netsim.Config{Seed: 14})
		a := s.peer(natKinds[0], fastConfig(false))
		victim := s.socket()
		const n = 10
		ids := make([]*koloid.Identity, n)
		for i := range ids {
			ids[i] = ident(t)
		}
		fake := fakeRelayOn(t, s.socket(), fakeAnswer{status: wire.StatusOK, class: wire.ClassConsistent, ip: victim.Addr().Addr(), ids: ids})
		var cw sync.WaitGroup
		errs := make([]error, n)
		for i := range n {
			cw.Add(1)
			go func() {
				defer cw.Done()
				rec := Record{PublicKey: ids[i].PublicKey(), Addr: victim.Addr(), relays: []relay{{server: fake, addr: victim.Addr()}}}
				_, errs[i] = a.Connect(ctx, rec)
			}()
		}
		cw.Wait()
		// maxDestAttempts of them punch and fail; the others find the host busy here.
		unreachable := 0
		for i, err := range errs {
			switch {
			case errors.Is(err, ErrUnreachable):
				unreachable++
			case !errors.Is(err, ErrTryLater):
				t.Fatalf("Connect %d: %v", i, err)
			}
		}
		if unreachable != maxDestAttempts {
			t.Fatalf("%d of %d Connects punched, want %d", unreachable, n, maxDestAttempts)
		}
		got := drain(victim, 200*time.Millisecond)
		for _, d := range got {
			if d[0]&0xC0 != 0 {
				t.Fatal("victim got a QUIC packet")
			}
		}
		if len(got) > maxDestAttempts*punch.ConsistentTries {
			t.Fatalf("victim got %d datagrams from %d records", len(got), n)
		}
	})
}

// One lying server does not flip the class or move our public IP.
func TestNATLiar(t *testing.T) {
	me := netip.MustParseAddrPort("192.0.2.9:4000")
	n := window(me, me, me)
	n.add(netip.MustParseAddrPort("198.51.100.1:4000"), netip.MustParseAddrPort("192.0.2.66:1"), natT0)
	if c := n.class(natT0); c != wire.ClassConsistent {
		t.Fatalf("class %v with one liar", c)
	}
	if ip, _ := n.publicIP(); ip != me.Addr() {
		t.Fatalf("publicIP %v", ip)
	}
	g := newNAT(time.Hour)
	g.add(netip.MustParseAddrPort("203.0.113.1:4000"), me, natT0)
	g.add(netip.MustParseAddrPort("203.0.113.2:4000"), netip.MustParseAddrPort("192.0.2.9:5000"), natT0)
	if c := g.class(natT0); c != wire.ClassUnknown || len(g.samples) != 1 {
		t.Fatalf("one /24: class %v", c)
	}
	if _, ok := window(me).publicIP(); ok {
		t.Fatal("public IP from one sample")
	}
}

// An address only one storer claims is not signed.
func TestStoreAtRejectsFakeObserved(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		ctx := testCtx(t, 10*time.Second)
		s := newSim(t, netsim.Config{Seed: 15})
		n := s.peer(natKinds[0], fastConfig(false))
		me := addrOf(n)
		n.mu.Lock()
		for i := range 3 {
			n.nat.add(netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 18, byte(150 + i), 1}), 4000), me, time.Now())
		}
		n.mu.Unlock()
		fake := s.socket()
		fakeAddr := netip.MustParseAddrPort("198.51.100.77:9")
		stop := make(chan struct{})
		var wg sync.WaitGroup
		var announced []netip.AddrPort
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 2048)
			for {
				select {
				case <-stop:
					return
				default:
				}
				fake.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
				k, from, err := fake.ReadFrom(buf)
				if err != nil {
					continue
				}
				id, m, err := wire.Decode(buf[:k])
				if err != nil {
					continue
				}
				if am, ok := m.(*wire.Announce); ok {
					announced = append(announced, am.Addr)
					if b, err := wire.Fit(id, &wire.AnnounceReply{Observed: fakeAddr, Status: wire.StatusRefused}, k); err == nil {
						fake.WriteTo(b, from)
					}
				}
			}
		}()
		a := &announcement{topic: topicOf("l3"), ctx: ctx, storers: map[netip.AddrPort]*storer{}, sigs: map[netip.AddrPort][wire.SigSize]byte{}}
		if _, ok := n.storeAt(ctx, a, fake.Addr(), [wire.TokenSize]byte{}, fakeAddr, storer{}); ok {
			t.Fatal("stored with a fake address")
		}
		if _, ok := n.storeAt(ctx, a, fake.Addr(), [wire.TokenSize]byte{}, me, storer{}); ok {
			t.Fatal("stored though refused")
		}
		close(stop)
		wg.Wait()
		for _, ad := range announced {
			if ad == fakeAddr {
				t.Fatal("signed and sent the address only the storer claimed")
			}
		}
		if _, ok := a.sigs[fakeAddr]; ok {
			t.Fatal("signature made for the fake address")
		}
	})
}

// Forged records cost a bounded number of signature checks.
func TestMergeVerifyCap(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newSim(t, netsim.Config{})
		n := s.server()
		topic := topicOf("l4")
		var answers []answer
		for i := range 100 {
			var recs []wire.Record
			for j := range wire.MaxRecords {
				recs = append(recs, wire.Record{Key: [32]byte{byte(i), byte(j), 1}, Addr: netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, byte(i), byte(j)}), 4000)})
			}
			answers = append(answers, answer{addr: netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 18, byte(i), 1}), 4000), reply: &wire.LookupReply{Records: recs}})
		}
		// One forged record from each of many servers still meets the overall cap.
		var many []answer
		for i := range 2 * maxVerify {
			many = append(many, answer{addr: netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 18, byte(i / 250), byte(i%250 + 1)}), 4000),
				reply: &wire.LookupReply{Records: []wire.Record{{Key: [32]byte{byte(i), byte(i >> 8), 2}, Addr: netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, 1, 1}), 4000)}}}})
		}
		if _, v := n.merge(topic, many); v > maxVerify {
			t.Fatalf("%d verifications across %d servers, cap %d", v, len(many), maxVerify)
		}
		got, verified := n.merge(topic, answers)
		if len(got) != 0 || verified > maxVerify {
			t.Fatalf("%d records, %d verifications, cap %d", len(got), verified, maxVerify)
		}
		if verified > len(answers) {
			t.Fatalf("%d verifications for %d responders: more than one per bad responder", verified, len(answers))
		}
		ok, err := records.Sign(ident(t), [32]byte(topic), netip.MustParseAddrPort("198.51.100.200:4000"))
		if err != nil {
			t.Fatal(err)
		}
		good := []answer{{addr: netip.MustParseAddrPort("198.18.200.1:4000"), reply: &wire.LookupReply{Records: []wire.Record{{Key: ok.Key, Addr: ok.Addr, Sig: ok.Sig}}}}}
		if got, _ := n.merge(topic, append(good, answers[:3]...)); len(got) != 1 {
			t.Fatalf("valid record lost: %d", len(got))
		}
	})
}

// Announce racing Close leaves nothing running and fails with ErrClosed.
func TestAnnounceCloseRace(t *testing.T) {
	checkGoroutines(t)
	for range 10 {
		srv := loopNode(t, fastConfig(true))
		n, err := New(context.Background(), "127.0.0.1:0", ident(t), fastConfig(false))
		if err != nil {
			t.Fatal(err)
		}
		if err := n.Bootstrap(context.Background(), []netip.AddrPort{addrOf(srv)}); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- n.Announce(context.Background(), topicOf("race")) }()
		n.Close()
		if err := <-done; err != nil && !errors.Is(err, ErrClosed) {
			t.Fatalf("Announce racing Close: %v", err)
		}
		if err := n.Announce(context.Background(), topicOf("race")); !errors.Is(err, ErrClosed) {
			t.Fatalf("Announce after Close: %v", err)
		}
	}
}

// Simultaneous open: a connection the peer dialed while our Connect ran goes to Accept, not closed.
func TestConnectKeepsPeerDial(t *testing.T) {
	checkGoroutines(t)
	a := loopNode(t, fastConfig(false))
	b := loopNode(t, fastConfig(false))
	silent := newRaw(t)
	rec := Record{PublicKey: b.id.PublicKey(), Addr: addrOf(b), relays: []relay{{server: silent.addr(), addr: addrOf(b)}}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := a.Connect(ctx, rec)
		done <- err
	}()
	if b, _ := silent.recv(5 * time.Second); b == nil {
		t.Fatal("the relay never got the CONNECT")
	}
	dctx, dcancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dcancel()
	cb, err := b.sl.Dial(dctx, addrOf(a), a.id.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	defer cb.Close()
	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done
	actx, acancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer acancel()
	ca, err := a.Accept(actx)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer ca.Close()
	if !bytes.Equal(ca.RemotePublicKey(), b.id.PublicKey()) {
		t.Fatal("accepted another key")
	}
	time.Sleep(500 * time.Millisecond)
	if ca.Context().Err() != nil || cb.Context().Err() != nil {
		t.Fatal("connection closed")
	}
}

// Stats reports the table, the store and the request counters.
func TestStats(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		ctx := testCtx(t, 20*time.Second)
		s := newSim(t, netsim.Config{Seed: 16})
		srv, other := s.server(), s.server()
		b := s.peer(natKinds[0], fastConfig(false))
		bootstrap(t, ctx, []*Node{other}, srv)
		bootstrap(t, ctx, []*Node{srv}, b)
		if st := srv.Stats(); st.Servers != 1 || st.Records != 0 || st.Requests == 0 {
			t.Fatalf("server stats %+v", st)
		}
		topic := topicOf("stats")
		if err := b.Announce(ctx, topic); err != nil {
			t.Fatal(err)
		}
		if st := srv.Stats(); st.Records != 1 {
			t.Fatalf("records %d after Announce", st.Records)
		}
		b.Unannounce(topic)
		time.Sleep(simTiming.ttl + 500*time.Millisecond)
		if st := srv.Stats(); st.Records != 0 {
			t.Fatalf("records %d after the TTL", st.Records)
		}
		go srv.Stats()
		srv.Close()
		srv.Stats()
	})
}

func TestStatsLimited(t *testing.T) {
	checkGoroutines(t)
	cfg := fastConfig(true)
	cfg.MaxRequestsPerIP, cfg.MaxRequestsPerPrefix, cfg.MaxRequests = 1, 1, 1
	n := loopNode(t, cfg)
	from := netip.MustParseAddrPort("198.51.100.1:5")
	now := time.Now().Add(time.Hour)
	b := encode(t, 1, &wire.Ping{}, pingSize)
	for range 5 {
		n.handlePacket(b, from, now)
	}
	if st := n.Stats(); st.Requests != 1 || st.Limited != 4 {
		t.Fatalf("stats %+v, want 1 request and 4 limited", st)
	}
}

func udp(ap netip.AddrPort) *net.UDPAddr { return net.UDPAddrFromAddrPort(ap) }

func udpAddrPort(a net.Addr) netip.AddrPort { return a.(*net.UDPAddr).AddrPort() }

// Check pings toward one network are budgeted, whatever the number of senders.
func TestConsiderBudget(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		s := newSim(t, netsim.Config{Seed: 17})
		n := s.server()
		var socks []*netsim.Conn
		for i := range 8 {
			h, err := s.net.AddHost(netip.AddrFrom4([4]byte{198, 51, 7, byte(10 + i)}))
			if err != nil {
				t.Fatal(err)
			}
			pc, err := h.ListenUDP(6000)
			if err != nil {
				t.Fatal(err)
			}
			defer pc.Close()
			socks = append(socks, pc)
			pc.WriteTo(encode(t, uint64(i), &wire.Ping{Flags: wire.NewFlags(uint8(i), true)}, 200), udp(addrOf(n)))
		}
		pings := 0
		for _, pc := range socks {
			for _, d := range drain(pc, 100*time.Millisecond) {
				if typ, _, _ := wire.Peek(d); typ == wire.TypePing {
					pings++
				}
			}
		}
		if pings == 0 || pings > 4 {
			t.Fatalf("%d check pings toward one /24 in one second, want 1 to 4", pings)
		}
	})
}

// A server changes r at most once per rChange.
func TestCollideRateLimited(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		s := newSim(t, netsim.Config{Seed: 18})
		n := s.server()
		other := netip.AddrPortFrom(addrOf(n).Addr(), addrOf(n).Port()+1)
		now := time.Now()
		n.mu.Lock()
		r0 := n.r.Load()
		n.collide(other, wire.NewFlags(uint8(r0), true), now)
		r1 := n.r.Load()
		n.collide(other, wire.NewFlags(uint8(r1), true), now.Add(n.tm.rChange/2))
		r2 := n.r.Load()
		n.collide(other, wire.NewFlags(uint8(r2), true), now.Add(n.tm.rChange))
		r3 := n.r.Load()
		// Our own address never counts as another server.
		n.collide(addrOf(n), wire.NewFlags(uint8(r3), true), now.Add(3*n.tm.rChange))
		r4 := n.r.Load()
		n.mu.Unlock()
		if r1 == r0 || r2 != r1 || r3 == r2 || r4 != r3 {
			t.Fatalf("r %d -> %d -> %d -> %d -> %d", r0, r1, r2, r3, r4)
		}
	})
}

// A server relays at most maxRelaysPerHost at once for one requester host and maxRelaysPerTarget for one target.
func TestRelayLimits(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		s := newSim(t, netsim.Config{Seed: 19})
		srv := s.server()
		token := func(pc *netsim.Conn) [wire.TokenSize]byte {
			t.Helper()
			pc.WriteTo(encode(t, 1, &wire.Ping{}, pingSize), udp(addrOf(srv)))
			for _, d := range drain(pc, 200*time.Millisecond) {
				if _, m, err := wire.Decode(d); err == nil {
					if pr, ok := m.(*wire.PingReply); ok {
						return pr.Token
					}
				}
			}
			t.Fatal("no token")
			return [wire.TokenSize]byte{}
		}
		// A record whose announcer never answers PUNCH keeps every relay waiting for RequestTimeout.
		silent := s.socket()
		topic := topicOf("relay-limits")
		rec, err := records.Sign(ident(t), [32]byte(topic), silent.Addr())
		if err != nil {
			t.Fatal(err)
		}
		stok := token(silent)
		full := func(pcs []*netsim.Conn, each int) int {
			t.Helper()
			toks := map[*netsim.Conn][wire.TokenSize]byte{}
			for _, pc := range pcs {
				toks[pc] = token(pc)
			}
			// Store (or refresh) the record just before, so its short simulated TTL has not run out.
			silent.WriteTo(encode(t, 2, &wire.Announce{Token: stok, Topic: rec.Topic, Key: rec.Key, Addr: rec.Addr, Sig: rec.Sig, Share: share(t)}, 0), udp(addrOf(srv)))
			drain(silent, 50*time.Millisecond)
			for _, pc := range pcs {
				for i := range each {
					c := &wire.Connect{Token: toks[pc], Topic: topic, Target: rec.Key, PunchID: [8]byte{byte(i + 1)}}
					pc.WriteTo(encode(t, uint64(10+i), c, wire.MaxSize), udp(addrOf(srv)))
				}
			}
			n := 0
			for _, pc := range pcs {
				for _, d := range drain(pc, 100*time.Millisecond) {
					if _, m, err := wire.Decode(d); err == nil {
						if cr, ok := m.(*wire.ConnectReply); ok && cr.Status == wire.StatusFull {
							n++
						}
					}
				}
			}
			return n
		}
		if got := full([]*netsim.Conn{s.socket()}, 6); got != 6-maxRelaysPerHost {
			t.Fatalf("one requester: %d refused at once, want %d", got, 6-maxRelaysPerHost)
		}
		time.Sleep(fastConfig(true).RequestTimeout + 200*time.Millisecond)
		var reqs []*netsim.Conn
		for range 6 {
			reqs = append(reqs, s.socket())
		}
		if got := full(reqs, 1); got != 6-maxRelaysPerTarget {
			t.Fatalf("one target: %d refused at once, want %d", got, 6-maxRelaysPerTarget)
		}
		time.Sleep(fastConfig(true).RequestTimeout + 200*time.Millisecond)
	})
}

// Our public IP moves only when more servers report the new one than the current one.
func TestSelfIPHysteresis(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		s := newSim(t, netsim.Config{Seed: 20})
		n := s.server()
		cur := addrOf(n)
		moved := netip.AddrPortFrom(netip.MustParseAddr("198.19.250.1"), cur.Port())
		report := func(i int, obs netip.AddrPort) {
			from := netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 18, byte(210 + i), 1}), 4000)
			n.observe(from, &wire.PingReply{Observed: obs, Flags: wire.NewFlags(uint8(i), true)}, time.Now())
		}
		report(0, cur)
		report(1, cur)
		report(2, moved)
		report(3, moved)
		n.mu.Lock()
		tie := n.selfIP
		n.mu.Unlock()
		report(4, moved)
		n.mu.Lock()
		after := n.selfIP
		n.mu.Unlock()
		if tie != cur.Addr() || after != moved.Addr() {
			t.Fatalf("self IP %v on a tie, %v after a majority; want %v then %v", tie, after, cur.Addr(), moved.Addr())
		}
	})
}

// Nothing starts after Close.
func TestSpawnAfterClose(t *testing.T) {
	checkGoroutines(t)
	n := loopNode(t, fastConfig(false))
	n.Close()
	ran := make(chan struct{}, 1)
	if n.spawn(func() { ran <- struct{}{} }) {
		t.Fatal("spawn after Close returned true")
	}
	select {
	case <-ran:
		t.Fatal("goroutine ran after Close")
	case <-time.After(50 * time.Millisecond):
	}
}

// TestIPv6NotUsed: no IPv6 address (plain, NAT64 or 6to4) enters the routing table, is shown to a requester or survives
// Lookup's merge, even with a valid signature.
func TestIPv6NotUsed(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		s := newSim(t, netsim.Config{Seed: 21})
		srv := s.server()
		pub := netip.MustParseAddrPort("203.0.113.5:1")
		v6 := []netip.AddrPort{
			netip.MustParseAddrPort("[2001:db8::5]:4000"),
			netip.MustParseAddrPort("[64:ff9b::cb00:7105]:4000"),
			netip.MustParseAddrPort("[2002:cb00:7105::1]:4000"),
		}
		srv.mu.Lock()
		for i, a := range v6 {
			srv.table.Insert(a, uint8(i), time.Now())
		}
		held, nodes := srv.table.Len(), srv.nodesFor([32]byte{}, pub)
		srv.mu.Unlock()
		if held != 0 || len(nodes) != 0 {
			t.Fatalf("table holds %d IPv6 entries, shows %+v", held, nodes)
		}
		topic := topicOf("ipv6")
		id := ident(t)
		reply := &wire.LookupReply{}
		for _, a := range v6 {
			key := [32]byte(id.PublicKey())
			sig, err := id.Sign(records.Context, append(append([]byte{0}, topic[:]...), key[:]...))
			if err != nil {
				t.Fatal(err)
			}
			reply.Nodes = append(reply.Nodes, wire.Node{Flags: wire.NewFlags(0, true), Addr: a})
			reply.Records = append(reply.Records, wire.Record{Key: key, Addr: a, Sig: [64]byte(sig)})
		}
		got, _ := srv.merge(topic, []answer{{addr: netip.MustParseAddrPort("198.51.100.1:4000"), reply: reply}})
		if len(got) != 0 {
			t.Fatalf("IPv6 records used: %+v", got)
		}
	})
}
