package kolodht

// Tests of the store, request and connect limits, over the simulator and loopback 127.0.0.1 only.

import (
	"errors"
	"math"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/ciranda-dev/kolo-dht/internal/netsim"
	"github.com/ciranda-dev/kolo-dht/internal/records"
	"github.com/ciranda-dev/kolo-dht/internal/table"
	"github.com/ciranda-dev/kolo-dht/internal/wire"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

// TestTopicPerNetwork: at the defaults, two hosts in one /24 cannot fill a topic, and a host in another /24 still stores.
func TestTopicPerNetwork(t *testing.T) {
	checkGoroutines(t)
	s := loopNode(t, fastConfig(true))
	topic, now := [32]byte{7}, time.Now()
	put := func(a netip.AddrPort) records.Result {
		r, err := records.Sign(ident(t), topic, a)
		if err != nil {
			t.Fatal(err)
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.store.Put(r, now)
	}
	stored := 0
	for i := 0; ; i++ {
		a := netip.AddrPortFrom(netip.AddrFrom4([4]byte{203, 0, 113, byte(1 + i%2)}), uint16(4000+i))
		if put(a) != records.Stored {
			break
		}
		stored++
	}
	if stored > s.cfg.MaxRecordsPerTopic/16 {
		t.Fatalf("one /24 stored %d records of one topic", stored)
	}
	if got := put(netip.MustParseAddrPort("198.51.100.1:4000")); got != records.Stored {
		t.Fatalf("a host in another /24: %v", got)
	}
}

// TestRecordSharesNoMaximum: MaxRecordsPerTopic and MaxRecordsPerIP take any positive value, and MaxRecords still bounds the store.
func TestRecordSharesNoMaximum(t *testing.T) {
	checkGoroutines(t)
	cfg := fastConfig(true)
	cfg.MaxRecords, cfg.MaxRecordsPerTopic, cfg.MaxRecordsPerIP = 16, math.MaxInt, 1<<20
	s := loopNode(t, cfg)
	topic, now := [32]byte{9}, time.Now()
	stored := 0
	for i := range 32 {
		r, err := records.Sign(ident(t), topic, netip.AddrPortFrom(netip.MustParseAddr("203.0.113.1"), uint16(4000+i)))
		if err != nil {
			t.Fatal(err)
		}
		s.mu.Lock()
		if s.store.Put(r, now) == records.Stored {
			stored++
		}
		s.mu.Unlock()
	}
	if stored != 16 {
		t.Fatalf("stored %d records of one topic and one address, want MaxRecords (16)", stored)
	}
}

// TestTransportIPv4Only gates the kolo-transport version: it listens on udp4 only, so New(":0") is IPv4. Binds nothing.
func TestTransportIPv4Only(t *testing.T) {
	if _, err := kolotransport.Listen(testCtx(t, time.Second), "127.0.0.1:0", &kolotransport.Config{Network: "udp"}); !errors.Is(err, kolotransport.ErrInvalidConfig) {
		t.Fatalf("Listen on network udp: %v, want ErrInvalidConfig", err)
	}
}

// TestLookupServesWhatFits: a LOOKUP reply carries as many of 16 records as fit in a datagram.
func TestLookupServesWhatFits(t *testing.T) {
	checkGoroutines(t)
	s := loopNode(t, fastConfig(true))
	topic, now := [32]byte{8}, time.Now()
	var recs []wire.Record
	for i := range wire.MaxRecords {
		r, err := records.Sign(ident(t), topic, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(5000+i)))
		if err != nil {
			t.Fatal(err)
		}
		s.mu.Lock()
		s.store.Put(r, now)
		s.mu.Unlock()
		recs = append(recs, wire.Record{Key: r.Key, Addr: r.Addr, Sig: r.Sig})
	}
	raw := newRaw(t)
	b, err := wire.Fit(1, &wire.LookupReply{Observed: raw.addr(), Records: recs}, wire.MaxSize)
	if err != nil {
		t.Fatal(err)
	}
	_, m, _ := wire.Decode(b)
	want := len(m.(*wire.LookupReply).Records)
	raw.send(addrOf(s), 2, &wire.Lookup{Topic: topic}, wire.MaxSize)
	_, rep := raw.reply(wait)
	lr, ok := rep.(*wire.LookupReply)
	if !ok || len(lr.Records) != want {
		t.Fatalf("reply %T with %d records, want %d", rep, len(lr.Records), want)
	}
}

// pinged reads socks for d and returns when each PING arrived; with reply set it answers them as a server would.
func pinged(t *testing.T, socks []*netsim.Conn, reply bool, d time.Duration) []time.Time {
	t.Helper()
	var mu sync.Mutex
	var at []time.Time
	var wg sync.WaitGroup
	deadline := time.Now().Add(d)
	for _, pc := range socks {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 2048)
			for {
				pc.SetReadDeadline(deadline)
				k, from, err := pc.ReadFrom(buf)
				if err != nil {
					return
				}
				id, m, err := wire.Decode(buf[:k])
				if _, ok := m.(*wire.Ping); err != nil || !ok {
					continue
				}
				mu.Lock()
				at = append(at, time.Now())
				mu.Unlock()
				if reply {
					if b, err := wire.Fit(id, &wire.PingReply{Observed: udpAddrPort(from), Flags: wire.NewFlags(0, true)}, k); err == nil {
						pc.WriteTo(b, from)
					}
				}
			}
		}()
	}
	wg.Wait()
	slices.SortFunc(at, func(a, b time.Time) int { return a.Compare(b) })
	return at
}

// TestConsiderMaxChecks: requests from more servers than maxChecks, in distinct /24s, get at most maxChecks check
// pings while those are unanswered.
func TestConsiderMaxChecks(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		s := newSim(t, netsim.Config{Seed: 31})
		n := s.server()
		var socks []*netsim.Conn
		for i := range maxChecks + 5 {
			pc := s.socket()
			socks = append(socks, pc)
			pc.WriteTo(encode(t, uint64(i), &wire.Ping{Flags: wire.NewFlags(uint8(i), true)}, 200), udp(addrOf(n)))
		}
		if got := len(pinged(t, socks, false, 100*time.Millisecond)); got != maxChecks {
			t.Fatalf("%d check pings, want %d", got, maxChecks)
		}
	})
}

// TestMaintainStaleChecks: a maintenance round pings staleChecks of the stale entries; answered ones are fresh, so
// the next round, simTiming.maintain later, pings the rest.
func TestMaintainStaleChecks(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		s := newSim(t, netsim.Config{Seed: 32})
		n := s.peer(natKinds[0], fastConfig(false))
		var socks []*netsim.Conn
		old := time.Now().Add(-table.Questionable - time.Minute)
		for range staleChecks + 3 {
			pc := s.socket()
			socks = append(socks, pc)
			n.mu.Lock()
			n.table.Insert(pc.Addr(), 0, old)
			n.mu.Unlock()
		}
		at := pinged(t, socks, true, 3*simTiming.maintain)
		if len(at) == 0 {
			t.Fatal("no maintenance round")
		}
		round := 1
		for round < len(at) && at[round].Sub(at[round-1]) < simTiming.maintain/2 {
			round++
		}
		if round != staleChecks {
			t.Fatalf("first round sent %d pings, want %d (all: %d)", round, staleChecks, len(at))
		}
	})
}

// TestConnectLocalBusy: with maxDestAttempts sessions open toward one host, Connect to another key at that host is
// ErrTryLater at once, not the peer's failure.
func TestConnectLocalBusy(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t, 5*time.Second)
	n := loopNode(t, fastConfig(false))
	srv := newRaw(t)
	host := netip.MustParseAddrPort("127.0.0.1:9")
	n.mu.Lock()
	for i := range maxDestAttempts {
		if _, ok := n.openSession([wire.PunchIDSize]byte{byte(i + 1)}, host); !ok {
			t.Fatal("session refused")
		}
	}
	n.mu.Unlock()
	rec := Record{PublicKey: ident(t).PublicKey(), Addr: host, relays: []relay{{server: srv.addr(), addr: netip.AddrPortFrom(host.Addr(), 10)}}}
	began := time.Now()
	if _, err := n.Connect(ctx, rec); !errors.Is(err, ErrTryLater) || time.Since(began) > 100*time.Millisecond {
		t.Fatalf("Connect: %v after %v, want ErrTryLater at once", err, time.Since(began))
	}
}

// TestConnectSameKeyBusy: while a Connect to a key runs, another Connect to that key is ErrTryLater at once.
func TestConnectSameKeyBusy(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t, 5*time.Second)
	n := loopNode(t, fastConfig(false))
	srv := newRaw(t)
	id := ident(t)
	key := [wire.KeySize]byte(id.PublicKey())
	n.mu.Lock()
	n.claims[key] = make(chan *kolosecure.Conn, 1)
	n.mu.Unlock()
	rec := Record{PublicKey: id.PublicKey(), Addr: srv.addr(), relays: []relay{{server: srv.addr(), addr: srv.addr()}}}
	began := time.Now()
	if _, err := n.Connect(ctx, rec); !errors.Is(err, ErrTryLater) || time.Since(began) > 100*time.Millisecond {
		t.Fatalf("Connect: %v after %v, want ErrTryLater at once", err, time.Since(began))
	}
}
