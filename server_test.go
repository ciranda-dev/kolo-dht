package kolodht

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/ciranda-dev/kolo-dht/internal/records"
	"github.com/ciranda-dev/kolo-dht/internal/wire"
)

// raw is a plain UDP socket on loopback that speaks the wire format by hand.
type raw struct {
	t  *testing.T
	pc *net.UDPConn
}

func newRaw(t *testing.T) *raw {
	t.Helper()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	return &raw{t: t, pc: pc}
}

func (r *raw) addr() netip.AddrPort { return r.pc.LocalAddr().(*net.UDPAddr).AddrPort() }

// send encodes m padded to size and returns the datagram's length.
func (r *raw) send(to netip.AddrPort, id uint64, m wire.Message, size int) int {
	r.t.Helper()
	b, err := wire.Encode(id, m, size)
	if err != nil {
		r.t.Fatal(err)
	}
	if _, err := r.pc.WriteToUDPAddrPort(b, to); err != nil {
		r.t.Fatal(err)
	}
	return len(b)
}

// recv returns the next datagram, or nil after wait.
func (r *raw) recv(wait time.Duration) ([]byte, netip.AddrPort) {
	r.t.Helper()
	r.pc.SetReadDeadline(time.Now().Add(wait))
	buf := make([]byte, 2048)
	n, from, err := r.pc.ReadFromUDPAddrPort(buf)
	if err != nil {
		return nil, netip.AddrPort{}
	}
	return buf[:n], from
}

func (r *raw) reply(wait time.Duration) (uint64, wire.Message) {
	r.t.Helper()
	b, _ := r.recv(wait)
	if b == nil {
		return 0, nil
	}
	id, m, err := wire.Decode(b)
	if err != nil {
		r.t.Fatalf("undecodable reply: %v", err)
	}
	return id, m
}

const wait = 300 * time.Millisecond

func TestNoAmplification(t *testing.T) {
	checkGoroutines(t)
	s := loopNode(t, fastConfig(true))
	ctx := testCtx(t, 10*time.Second)
	other := loopNode(t, fastConfig(true))
	if err := other.Bootstrap(ctx, []netip.AddrPort{addrOf(s)}); err != nil {
		t.Fatal(err)
	}
	if err := s.Bootstrap(ctx, []netip.AddrPort{addrOf(other)}); err != nil {
		t.Fatal(err)
	}
	r := newRaw(t)
	srvFlag := wire.NewFlags(5, true)
	reqs := []wire.Message{
		&wire.Ping{},
		&wire.Ping{Flags: srvFlag},
		&wire.FindNode{},
		&wire.FindNode{Flags: srvFlag},
		&wire.Lookup{},
		&wire.Lookup{Flags: srvFlag},
		&wire.Announce{Addr: r.addr()},
		&wire.Connect{},
		&wire.Probe{Nonce: [8]byte{1}},
	}
	replied := 0
	// One batch per size: each request has a fresh source, so a check ping from an earlier one cannot land on a
	// later one, and the batch shares one silence window.
	for _, size := range []int{0, 64, 100, 200, wire.MaxSize} {
		var srcs []*raw
		var sent []int
		var sentTypes []wire.Message
		for i, m := range reqs {
			if _, err := wire.Encode(7, m, size); err != nil {
				continue
			}
			src := newRaw(t)
			srcs, sent, sentTypes = append(srcs, src), append(sent, src.send(addrOf(s), uint64(i), m, size)), append(sentTypes, m)
		}
		time.Sleep(wait)
		for i, src := range srcs {
			total := 0
			for {
				b, _ := src.recv(5 * time.Millisecond)
				if b == nil {
					break
				}
				total += len(b)
			}
			if total > 0 {
				replied++
			}
			if total > sent[i] {
				t.Fatalf("%T of %d bytes got %d bytes back", sentTypes[i], sent[i], total)
			}
		}
	}
	if replied == 0 {
		t.Fatal("no request got a reply")
	}
	// An unpadded FIND_NODE is too small for any reply.
	n := r.send(addrOf(s), 8, &wire.FindNode{}, 0)
	if b, _ := r.recv(wait); b != nil {
		t.Fatalf("FIND_NODE of %d bytes got %d", n, len(b))
	}
	// A padded one gets the server's nodes.
	r.send(addrOf(s), 9, &wire.FindNode{}, wire.MaxSize)
	_, m := r.reply(wait)
	if fr, ok := m.(*wire.FindNodeReply); !ok || len(fr.Nodes) != 1 || fr.Nodes[0].Addr != addrOf(other) {
		t.Fatalf("FIND_NODE reply %+v", m)
	}
}

func pingToken(t *testing.T, r *raw, to netip.AddrPort) [wire.TokenSize]byte {
	t.Helper()
	r.send(to, 1, &wire.Ping{}, pingSize)
	_, m := r.reply(wait)
	pr, ok := m.(*wire.PingReply)
	if !ok || pr.Observed != r.addr() {
		t.Fatalf("PING reply %+v", m)
	}
	return pr.Token
}

// share returns a new X25519 public key, as an announcer sends in ANNOUNCE.
func share(t *testing.T) [wire.ShareSize]byte {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return [wire.ShareSize]byte(k.PublicKey().Bytes())
}

func announceFrom(t *testing.T, r *raw, to netip.AddrPort, tok [wire.TokenSize]byte, addr netip.AddrPort) wire.Status {
	t.Helper()
	rec, err := records.Sign(ident(t), topicOf("tok"), addr)
	if err != nil {
		t.Fatal(err)
	}
	r.send(to, 2, &wire.Announce{Token: tok, Topic: rec.Topic, Key: rec.Key, Addr: rec.Addr, Sig: rec.Sig, Share: share(t)}, 0)
	_, m := r.reply(wait)
	ar, ok := m.(*wire.AnnounceReply)
	if !ok {
		t.Fatalf("ANNOUNCE reply %+v", m)
	}
	return ar.Status
}

func TestTokenRequired(t *testing.T) {
	checkGoroutines(t)
	s := loopNode(t, fastConfig(true))
	r, r2 := newRaw(t), newRaw(t)
	if got := announceFrom(t, r, addrOf(s), [wire.TokenSize]byte{}, r.addr()); got != wire.StatusBadToken {
		t.Fatalf("no token: %v", got)
	}
	tok := pingToken(t, r, addrOf(s))
	if got := announceFrom(t, r2, addrOf(s), tok, r2.addr()); got != wire.StatusBadToken {
		t.Fatalf("token of another port: %v", got)
	}
	if got := announceFrom(t, r, addrOf(s), tok, r2.addr()); got != wire.StatusRefused {
		t.Fatalf("record for another address: %v", got)
	}
	if got := announceFrom(t, r, addrOf(s), tok, r.addr()); got != wire.StatusOK {
		t.Fatalf("valid announce: %v", got)
	}
	s.mu.Lock()
	held := s.store.Len(time.Now())
	s.mu.Unlock()
	if held != 1 {
		t.Fatalf("store holds %d records", held)
	}

	// CONNECT needs padding and a token, and a record to relay to.
	r.send(addrOf(s), 3, &wire.Connect{Token: tok}, 0)
	if b, _ := r.recv(wait); b != nil {
		t.Fatal("unpadded CONNECT answered")
	}
	r.send(addrOf(s), 4, &wire.Connect{}, wire.MaxSize)
	if _, m := r.reply(wait); m == nil || m.(*wire.ConnectReply).Status != wire.StatusBadToken {
		t.Fatalf("CONNECT without token: %+v", m)
	}
	r.send(addrOf(s), 5, &wire.Connect{Token: tok}, wire.MaxSize)
	if _, m := r.reply(wait); m == nil || m.(*wire.ConnectReply).Status != wire.StatusNoRecord {
		t.Fatalf("CONNECT without record: %+v", m)
	}
}

func TestClientServesOnlyPings(t *testing.T) {
	checkGoroutines(t)
	c := loopNode(t, fastConfig(false))
	r := newRaw(t)
	for _, m := range []wire.Message{&wire.FindNode{}, &wire.Lookup{}, &wire.Announce{Addr: r.addr()}, &wire.Connect{}} {
		r.send(addrOf(c), 1, m, wire.MaxSize)
		if b, _ := r.recv(wait); b != nil {
			t.Fatalf("client answered %T", m)
		}
	}
	r.send(addrOf(c), 2, &wire.Ping{Flags: wire.NewFlags(0, true)}, pingSize)
	_, m := r.reply(wait)
	if pr, ok := m.(*wire.PingReply); !ok || pr.Flags.Server() {
		t.Fatalf("client PING reply %+v", m)
	}
}

func TestClientNotRouted(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t, 10*time.Second)
	s := loopNode(t, fastConfig(true))
	c := loopNode(t, fastConfig(false))
	if err := c.Bootstrap(ctx, []netip.AddrPort{addrOf(s)}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	s.mu.Lock()
	n := s.table.Len()
	s.mu.Unlock()
	if n != 0 {
		t.Fatalf("server table holds %d entries after a client bootstrapped", n)
	}
	c.mu.Lock()
	n = c.table.Len()
	c.mu.Unlock()
	if n != 1 {
		t.Fatalf("client table holds %d entries, want the server", n)
	}
}

func TestPunchRefused(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t, 10*time.Second)
	s := loopNode(t, fastConfig(true))
	b := loopNode(t, fastConfig(false))
	if err := b.Bootstrap(ctx, []netip.AddrPort{addrOf(s)}); err != nil {
		t.Fatal(err)
	}
	topic := topicOf("refused")
	if err := b.Announce(ctx, topic); err != nil {
		t.Fatal(err)
	}
	r := newRaw(t)
	p := &wire.Punch{Topic: topic, Target: b.key, Key: [32]byte{9}, Addr: r.addr()}
	r.send(addrOf(b), 1, p, 0)
	// A PUNCH without its storer's MAC is dropped: no reply, and nothing to the address named in it.
	if b, _ := r.recv(wait); b != nil {
		t.Fatalf("PUNCH from a non-storer got %d bytes back", len(b))
	}
}

func TestResponseMatching(t *testing.T) {
	checkGoroutines(t)
	n := loopNode(t, fastConfig(false))
	r, r2 := newRaw(t), newRaw(t)
	done := make(chan wire.Message, 1)
	go func() {
		m, _ := n.request(context.Background(), r.addr(), &wire.Ping{}, pingSize, 2*time.Second)
		done <- m
	}()
	b, _ := r.recv(time.Second)
	id, _, err := wire.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	good := &wire.PingReply{Observed: addrOf(n), Flags: wire.NewFlags(1, false)}
	r2.send(addrOf(n), id, good, 0)                                    // wrong source
	r.send(addrOf(n), id, &wire.FindNodeReply{Observed: addrOf(n)}, 0) // wrong type
	r.send(addrOf(n), id+1, good, 0)                                   // wrong id
	select {
	case m := <-done:
		t.Fatalf("request took a wrong reply: %+v", m)
	case <-time.After(wait):
	}
	r.send(addrOf(n), id, good, 0)
	if m := <-done; m == nil || m.(*wire.PingReply).Flags != good.Flags {
		t.Fatalf("request got %+v", m)
	}
}

func TestRateLimit(t *testing.T) {
	checkGoroutines(t)
	cfg := fastConfig(true)
	cfg.MaxRequestsPerIP = 5
	s := loopNode(t, cfg)
	r := newRaw(t)
	for i := range 50 {
		r.send(addrOf(s), uint64(i), &wire.Ping{}, pingSize)
	}
	got := 0
	for {
		b, _ := r.recv(wait)
		if b == nil {
			break
		}
		got++
	}
	if got < 1 || got > 10 {
		t.Fatalf("%d replies to 50 pings with MaxRequestsPerIP 5", got)
	}
}

func TestAnnounceLimit(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t, 10*time.Second)
	s := loopNode(t, fastConfig(true))
	cfg := fastConfig(false)
	cfg.MaxAnnouncements = 1
	b := loopNode(t, cfg)
	if err := b.Bootstrap(ctx, []netip.AddrPort{addrOf(s)}); err != nil {
		t.Fatal(err)
	}
	if err := b.Announce(ctx, topicOf("one")); err != nil {
		t.Fatal(err)
	}
	if err := b.Announce(ctx, topicOf("one")); err != nil {
		t.Fatalf("announcing the same topic again: %v", err)
	}
	if err := b.Announce(ctx, topicOf("two")); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("second topic: %v, want ErrInvalidArgument", err)
	}
	b.Unannounce(topicOf("one"))
	if err := b.Announce(ctx, topicOf("two")); err != nil {
		t.Fatalf("after Unannounce: %v", err)
	}
}

func TestRecordLimitsAtServer(t *testing.T) {
	checkGoroutines(t)
	cfg := fastConfig(true)
	cfg.MaxRecordsPerIP = 1
	s := loopNode(t, cfg)
	r := newRaw(t)
	tok := pingToken(t, r, addrOf(s))
	if got := announceFrom(t, r, addrOf(s), tok, r.addr()); got != wire.StatusOK {
		t.Fatalf("first: %v", got)
	}
	if got := announceFrom(t, r, addrOf(s), tok, r.addr()); got != wire.StatusFull {
		t.Fatalf("second key from one IP: %v, want full", got)
	}
}

func TestServerChecksOnlyServers(t *testing.T) {
	checkGoroutines(t)
	s := loopNode(t, fastConfig(true))
	for _, server := range []bool{false, true} {
		r := newRaw(t)
		// Another r than the server's own, which on one loopback IP would be the server's own ID.
		r.send(addrOf(s), 1, &wire.Ping{Flags: wire.NewFlags(uint8(s.r.Load()+1), server)}, pingSize)
		if _, m := r.reply(wait); m == nil {
			t.Fatal("no PING reply")
		}
		// A requester that says it is a server is pinged back before it may enter the table.
		_, m := r.reply(wait)
		if _, ok := m.(*wire.Ping); ok != server {
			t.Fatalf("server flag %v: got %+v", server, m)
		}
	}
}
