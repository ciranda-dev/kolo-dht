package kolodht

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/ciranda-dev/kolo-dht/internal/addrs"
	"github.com/ciranda-dev/kolo-dht/internal/netsim"
	"github.com/ciranda-dev/kolo-dht/internal/punch"
	"github.com/ciranda-dev/kolo-dht/internal/records"
	"github.com/ciranda-dev/kolo-dht/internal/table"
	"github.com/ciranda-dev/kolo-dht/internal/wire"
	koloid "github.com/ciranda-dev/kolo-id"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

func TestNewErrors(t *testing.T) {
	checkGoroutines(t)
	ctx := context.Background()
	if _, err := New(ctx, "127.0.0.1:0", nil, nil); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("nil identity: %v", err)
	}
	if _, err := New(ctx, "127.0.0.1:0", &koloid.Identity{}, nil); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("zero identity: %v", err)
	}
	if _, err := New(ctx, "127.0.0.1:0", ident(t), &Config{MaxInflight: 1}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("bad MaxInflight: %v", err)
	}
	bad := &Config{Secure: &kolosecure.Config{Transport: &kolotransport.Config{MaxConns: -1}}}
	if _, err := New(ctx, "127.0.0.1:0", ident(t), bad); !errors.Is(err, ErrInvalidConfig) || !errors.Is(err, kolotransport.ErrInvalidConfig) {
		t.Fatalf("bad transport config: %v", err)
	}
	bad = &Config{Secure: &kolosecure.Config{HandshakeTimeout: time.Hour}}
	if _, err := New(ctx, "127.0.0.1:0", ident(t), bad); !errors.Is(err, ErrInvalidConfig) || !errors.Is(err, kolosecure.ErrInvalidConfig) {
		t.Fatalf("bad secure config: %v", err)
	}
	if _, err := New(ctx, "256.0.0.1:0", ident(t), nil); err == nil {
		t.Fatal("bad address accepted")
	}
}

func TestBootstrapErrors(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t, 10*time.Second)
	n := loopNode(t, fastConfig(false))
	if err := n.Bootstrap(ctx, []netip.AddrPort{}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("no servers: %v", err)
	}
	if err := n.Bootstrap(ctx, []netip.AddrPort{netip.MustParseAddrPort("0.0.0.0:1"), netip.MustParseAddrPort("224.0.0.1:1")}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("unusable servers: %v", err)
	}
	dead := newRaw(t)
	if err := n.Bootstrap(ctx, []netip.AddrPort{dead.addr()}); !errors.Is(err, ErrNoNodes) {
		t.Fatalf("silent server: %v", err)
	}
	// A client answers pings but is not a server.
	c := loopNode(t, fastConfig(false))
	if err := n.Bootstrap(ctx, []netip.AddrPort{addrOf(c)}); !errors.Is(err, ErrNoNodes) {
		t.Fatalf("client as server: %v", err)
	}
	n.mu.Lock()
	held := n.table.Len()
	n.mu.Unlock()
	if held != 0 {
		t.Fatalf("a client that answered a ping entered the table")
	}
	if _, err := n.Lookup(ctx, topicOf("x")); !errors.Is(err, ErrNoNodes) {
		t.Fatalf("Lookup with an empty table: %v", err)
	}
	if err := n.Announce(ctx, topicOf("x")); !errors.Is(err, ErrNoNodes) {
		t.Fatalf("Announce with an empty table: %v", err)
	}
}

func TestConnectErrors(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t, 10*time.Second)
	n := loopNode(t, fastConfig(false))
	if _, err := n.Connect(ctx, Record{}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("empty record: %v", err)
	}
	r := Record{PublicKey: n.id.PublicKey(), relays: []relay{{server: netip.MustParseAddrPort("127.0.0.1:1")}}}
	if _, err := n.Connect(ctx, r); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("own key: %v", err)
	}
	dead := newRaw(t)
	r = Record{PublicKey: ident(t).PublicKey(), relays: []relay{{server: dead.addr(), addr: dead.addr()}}}
	_, err := n.Connect(ctx, r)
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("silent relay: %v", err)
	}
	if strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("error carries an address: %v", err)
	}
}

func TestContextCanceled(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		ctx := testCtx(t, 10*time.Second)
		s := newSim(t, netsim.Config{})
		srv := s.server()
		n := s.peer(natKinds[0], fastConfig(false))
		if err := n.Bootstrap(ctx, []netip.AddrPort{addrOf(srv)}); err != nil {
			t.Fatal(err)
		}
		done, cancel := context.WithCancel(context.Background())
		cancel()
		rec := Record{PublicKey: ident(t).PublicKey(), relays: []relay{{server: addrOf(srv), addr: addrOf(srv)}}}
		calls := map[string]func(context.Context) error{
			"Bootstrap": func(c context.Context) error { return n.Bootstrap(c, []netip.AddrPort{addrOf(srv)}) },
			"Announce":  func(c context.Context) error { return n.Announce(c, topicOf("ctx")) },
			"Lookup":    func(c context.Context) error { _, err := n.Lookup(c, topicOf("ctx")); return err },
			"Connect":   func(c context.Context) error { _, err := n.Connect(c, rec); return err },
			"Accept":    func(c context.Context) error { _, err := n.Accept(c); return err },
		}
		for name, f := range calls {
			if err := f(done); !errors.Is(err, context.Canceled) {
				t.Errorf("%s with a canceled context: %v", name, err)
			}
		}
		short, cancel2 := context.WithTimeout(ctx, 50*time.Millisecond)
		defer cancel2()
		if _, err := n.Accept(short); !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("Accept: %v", err)
		}
		dead := s.socketIn(18)
		short, cancel3 := context.WithTimeout(ctx, 100*time.Millisecond)
		defer cancel3()
		if err := n.Bootstrap(short, []netip.AddrPort{dead.Addr()}); !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("Bootstrap to a silent server: %v", err)
		}
	})
}

// lateTimer is a context whose deadline has passed but whose Err stays nil and whose Done never closes, as when the
// runtime has not yet run the context's timer: on a coarse timer a request's own timeout can fire first.
type lateTimer struct {
	context.Context
	deadline time.Time
}

func (c lateTimer) Deadline() (time.Time, bool) { return c.deadline, true }

func TestDeadlinePassedBeforeContextTimer(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t, 20*time.Second)
	s := loopNode(t, fastConfig(true))
	n := loopNode(t, fastConfig(false))
	silent := addrOf(s)
	if err := n.Bootstrap(ctx, []netip.AddrPort{silent}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	rec := Record{PublicKey: ident(t).PublicKey(), relays: []relay{{server: silent, addr: silent}}}
	calls := map[string]func(context.Context) error{
		"Bootstrap": func(c context.Context) error { return n.Bootstrap(c, []netip.AddrPort{silent}) },
		"Announce":  func(c context.Context) error { return n.Announce(c, topicOf("late")) },
		"Lookup":    func(c context.Context) error { _, err := n.Lookup(c, topicOf("late")); return err },
		"Connect":   func(c context.Context) error { _, err := n.Connect(c, rec); return err },
	}
	for name, f := range calls {
		late := lateTimer{context.Background(), time.Now().Add(10 * time.Millisecond)}
		if err := f(late); !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("%s with a deadline past before the context's timer ran: %v", name, err)
		}
	}
}

func TestClosed(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t, 10*time.Second)
	n, err := New(ctx, "127.0.0.1:0", ident(t), fastConfig(true))
	if err != nil {
		t.Fatal(err)
	}
	accepting := make(chan error, 1)
	go func() {
		_, err := n.Accept(ctx)
		accepting <- err
	}()
	time.Sleep(20 * time.Millisecond)
	if err := n.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-accepting; !errors.Is(err, ErrClosed) {
		t.Fatalf("Accept during Close: %v", err)
	}
	n.Close()
	rec := Record{PublicKey: ident(t).PublicKey(), relays: []relay{{server: netip.MustParseAddrPort("127.0.0.1:1")}}}
	for name, err := range map[string]error{
		"Bootstrap": n.Bootstrap(ctx, []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:1")}),
		"Announce":  n.Announce(ctx, topicOf("x")),
		"Lookup":    func() error { _, err := n.Lookup(ctx, topicOf("x")); return err }(),
		"Connect":   func() error { _, err := n.Connect(ctx, rec); return err }(),
		"Accept":    func() error { _, err := n.Accept(ctx); return err }(),
	} {
		if !errors.Is(err, ErrClosed) {
			t.Errorf("%s after Close: %v", name, err)
		}
	}
	n.Unannounce(topicOf("x"))
}

func TestAcceptQueueFull(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		ctx := testCtx(t, 20*time.Second)
		s := newSim(t, netsim.Config{Seed: 3})
		servers := []*Node{s.server(), s.server(), s.server()}
		bootstrap(t, ctx, servers[1:], servers[0])
		bcfg := fastConfig(false)
		bcfg.Secure.MaxPending = 1
		b := s.peer(natKinds[0], bcfg)
		a1, a2 := s.peer(natKinds[0], fastConfig(false)), s.peer(natKinds[0], fastConfig(false))
		bootstrap(t, ctx, servers, a1, a2, b)
		topic := topicOf("queue")
		if err := b.Announce(ctx, topic); err != nil {
			t.Fatal(err)
		}
		var conns []*kolosecure.Conn
		for _, a := range []*Node{a1, a2} {
			recs, err := a.Lookup(ctx, topic)
			if err != nil || len(recs) != 1 {
				t.Fatalf("Lookup: %v", err)
			}
			c, err := a.Connect(ctx, recs[0])
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			conns = append(conns, c)
			// Connect returns when the dialer is done; the listener still checks its proof and hands the connection
			// over, and until then it holds the listener's one pending slot and refuses a new connection.
			synctest.Wait()
		}
		select {
		case <-conns[1].Context().Done():
		case <-time.After(5 * time.Second):
			t.Fatal("second connection still open with a full queue")
		}
		// Checked before Accept and Close: closing the accepted side ends the first one too.
		if conns[0].Context().Err() != nil {
			t.Fatal("first connection closed")
		}
		c, err := b.Accept(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if !bytes.Equal(c.RemotePublicKey(), a1.id.PublicKey()) {
			t.Fatal("Accept returned a connection that is not the first")
		}
	})
}

func TestAddressScope(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		s := newSim(t, netsim.Config{})
		srv := s.server()
		// A loopback or private server in the table is never shown to a public requester.
		srv.mu.Lock()
		srv.table.Insert(netip.MustParseAddrPort("192.168.1.9:4000"), 0, time.Now())
		srv.table.Insert(netip.MustParseAddrPort("198.51.100.9:4000"), 0, time.Now())
		pub := srv.nodesFor(table.ID{}, netip.MustParseAddrPort("203.0.113.5:1"))
		lan := srv.nodesFor(table.ID{}, netip.MustParseAddrPort("192.168.1.5:1"))
		srv.mu.Unlock()
		if len(pub) != 1 || pub[0].Addr != netip.MustParseAddrPort("198.51.100.9:4000") {
			t.Fatalf("nodes for a public requester: %+v", pub)
		}
		if len(lan) != 2 {
			t.Fatalf("nodes for a LAN requester: %+v", lan)
		}
		// A record with a private address from a public server is dropped, even with a valid signature.
		topic := topicOf("scope")
		priv, err := records.Sign(ident(t), [32]byte(topic), netip.MustParseAddrPort("10.0.0.5:4000"))
		if err != nil {
			t.Fatal(err)
		}
		ok, err := records.Sign(ident(t), [32]byte(topic), netip.MustParseAddrPort("198.51.100.20:4000"))
		if err != nil {
			t.Fatal(err)
		}
		forged := ok
		forged.Sig[0] ^= 1
		reply := &wire.LookupReply{Records: []wire.Record{
			{Key: priv.Key, Addr: priv.Addr, Sig: priv.Sig},
			{Key: ok.Key, Addr: ok.Addr, Sig: ok.Sig, Age: 3},
			{Key: forged.Key, Addr: netip.MustParseAddrPort("198.51.100.21:4000"), Sig: forged.Sig},
		}}
		got, _ := srv.merge(topic, []answer{{addr: netip.MustParseAddrPort("203.0.113.1:4000"), reply: reply}})
		if len(got) != 1 || got[0].Addr != ok.Addr {
			t.Fatalf("merged %+v", got)
		}
	})
}

func TestProbeSession(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		s := newSim(t, netsim.Config{})
		n := s.server()
		p, q := s.socket(), s.socket()
		pid := [8]byte{1}
		n.mu.Lock()
		ses, ok := n.openSession(pid, p.Addr())
		_, ok2 := n.openSession([8]byte{2}, netip.AddrPortFrom(p.Addr().Addr(), 9))
		_, ok3 := n.openSession([8]byte{3}, netip.AddrPortFrom(p.Addr().Addr(), 10))
		_, dup := n.openSession(pid, q.Addr())
		n.mu.Unlock()
		if !ok || !ok2 || ok3 || dup {
			t.Fatalf("openSession: %v %v %v %v, want two per host and unique ids", ok, ok2, ok3, dup)
		}
		n.probe(ses, p.Addr())
		got := drain(p, 50*time.Millisecond)
		if len(got) != 1 {
			t.Fatalf("one probe sent %d datagrams", len(got))
		}
		_, m, err := wire.Decode(got[0])
		if pr, ok := m.(*wire.Probe); err != nil || !ok || pr.Nonce != ses.nonce || pr.Echo != [8]byte{} {
			t.Fatalf("probe %+v %v", m, err)
		}
		// Probes with a nonce get one answer each, the same size, at most maxProbeReplies in all.
		in := encode(t, 0, &wire.Probe{PunchID: pid, Nonce: [8]byte{9}}, 0)
		for range maxProbeReplies + 3 {
			q.WriteTo(in, udp(addrOf(n)))
		}
		got = drain(q, 100*time.Millisecond)
		if len(got) != maxProbeReplies {
			t.Fatalf("%d answers to %d probes", len(got), maxProbeReplies+3)
		}
		for _, d := range got {
			_, m, _ := wire.Decode(d)
			if pr := m.(*wire.Probe); len(d) != len(in) || pr.Echo != [8]byte{9} || pr.Nonce != ses.nonce {
				t.Fatalf("answer %+v of %d bytes", pr, len(d))
			}
		}
		// An echo proves only an address our nonce went to: q was answered, so it counts; a stranger does not.
		r := s.socket()
		r.WriteTo(encode(t, 0, &wire.Probe{PunchID: pid, Echo: ses.nonce}, 0), udp(addrOf(n)))
		time.Sleep(20 * time.Millisecond)
		select {
		case v := <-ses.valid:
			t.Fatalf("stranger %s proved", v.addr)
		default:
		}
		p.WriteTo(encode(t, 0, &wire.Probe{PunchID: pid, Echo: ses.nonce}, 0), udp(addrOf(n)))
		select {
		case v := <-ses.valid:
			if v.addr != p.Addr() || v.holder != 0 {
				t.Fatalf("proved %+v, want %s on the node socket", v, p.Addr())
			}
		case <-time.After(time.Second):
			t.Fatal("echo did not prove the address")
		}
		n.closeSession(ses)
		n.mu.Lock()
		left := n.sessionHosts[addrs.Host(p.Addr().Addr())]
		n.mu.Unlock()
		if left != 1 {
			t.Fatalf("%d sessions counted after close, want 1", left)
		}
	})
}

// TestBirthdayDialLoopback runs the random side's commit on real udp4 sockets: a dial from holder 1 through
// kolotransport.ListenConn; the socket leaves the budget once the connection is up and closes with it.
func TestBirthdayDialLoopback(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t, 10*time.Second)
	cfg := fastConfig(false)
	cfg.MaxPunchSockets = punch.Sockets - 1
	n, p := loopNode(t, cfg), loopNode(t, fastConfig(false))
	peer := addrOf(p)
	n.mu.Lock()
	s, ok := n.openSession([wire.PunchIDSize]byte{1}, peer)
	g, ok2 := n.budget.Acquire(punch.Connector, peer.Addr(), punch.Sockets-1, time.Now())
	n.mu.Unlock()
	if !ok || !ok2 {
		t.Fatalf("session %v, grant %v", ok, ok2)
	}
	defer n.closeSession(s)
	defer g.Done(time.Now())
	b, err := n.openBirthday(s, peer, g)
	if err != nil {
		t.Fatal(err)
	}
	defer b.close()
	c, err := b.dial(ctx, proof{peer, 1}, p.key[:])
	if err != nil {
		t.Fatal(err)
	}
	pc, err := p.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	if from := pc.RemoteAddr().(*net.UDPAddr).AddrPort(); from.Port() == addrOf(n).Port() {
		t.Fatalf("connection came from the node socket %v", from)
	}
	echo(t, ctx, c, pc)
	if got := n.budget.Sockets(); got != 0 {
		t.Fatalf("%d sockets held with the connection open, want 0", got)
	}
	c.Close()
}

func TestErrorsHaveNoPeerContent(t *testing.T) {
	for _, err := range []error{ErrInvalidConfig, ErrInvalidArgument, ErrClosed, ErrNoNodes, ErrNotStored, ErrUnreachable, ErrTryLater} {
		if !strings.HasPrefix(err.Error(), "kolodht: ") || strings.ContainsAny(err.Error(), "0123456789") {
			t.Errorf("sentinel %q", err)
		}
	}
}
