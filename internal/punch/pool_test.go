package punch

// Pool tests over internal/netsim only; nothing leaves the process.

import (
	"errors"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ciranda-dev/kolo-dht/internal/netsim"
	"golang.org/x/net/ipv4"
)

func checkGoroutines(t *testing.T) {
	t.Helper()
	before := goroutines()
	t.Cleanup(func() {
		deadline := time.Now().Add(5 * time.Second)
		for {
			var leaked []string
			for id, stack := range goroutines() {
				if _, ok := before[id]; !ok {
					leaked = append(leaked, stack)
				}
			}
			if len(leaked) == 0 {
				return
			}
			if time.Now().After(deadline) {
				t.Errorf("%d goroutines leaked:\n%s", len(leaked), strings.Join(leaked, "\n\n"))
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
}

func goroutines() map[string]string {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	out := make(map[string]string)
	for _, stack := range strings.Split(string(buf), "\n\n") {
		if id, _, ok := strings.Cut(strings.TrimPrefix(stack, "goroutine "), " "); ok {
			out[id] = stack
		}
	}
	return out
}

// spawner runs goroutines the test waits for.
type spawner struct {
	wg      sync.WaitGroup
	running atomic.Int32
	closed  bool
}

func (s *spawner) spawn(f func()) bool {
	if s.closed {
		return false
	}
	s.wg.Add(1)
	s.running.Add(1)
	go func() {
		defer s.wg.Done()
		defer s.running.Add(-1)
		f()
	}()
	return true
}

type got struct {
	i    int
	b    string
	from netip.AddrPort
}

type poolNet struct {
	net         *netsim.Network
	local, peer *netsim.Host
	peerConn    *netsim.Conn
	mu          sync.Mutex
	taps        []netsim.Packet
}

// newPoolNet has a public host for the pool, a public peer listening on 7000, and a tap on every packet.
func newPoolNet(t *testing.T) *poolNet {
	p := &poolNet{}
	p.net = netsim.New(netsim.Config{Seed: 1, Tap: func(pk netsim.Packet) {
		p.mu.Lock()
		p.taps = append(p.taps, pk)
		p.mu.Unlock()
	}})
	var err error
	if p.local, err = p.net.AddHost(netip.MustParseAddr("198.18.0.1")); err != nil {
		t.Fatal(err)
	}
	if p.peer, err = p.net.AddHost(netip.MustParseAddr("198.18.1.1")); err != nil {
		t.Fatal(err)
	}
	if p.peerConn, err = p.peer.ListenUDP(7000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.peerConn.Close() })
	return p
}

func (p *poolNet) listen() (net.PacketConn, error) { return p.local.ListenUDP(0) }

// holderAddr sends from holder i and returns the source address the tap saw.
func (p *poolNet) holderAddr(t *testing.T, pool *Pool, i int) netip.AddrPort {
	t.Helper()
	if err := pool.Send(i, []byte("open")); err != nil {
		t.Fatal(err)
	}
	pkts := p.packets()
	return pkts[len(pkts)-1].From
}

func (p *poolNet) packets() []netsim.Packet {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]netsim.Packet(nil), p.taps...)
}

func open(t *testing.T, p *poolNet, sp *spawner, k int, ch chan got) *Pool {
	t.Helper()
	pool, err := Open(k, p.listen, 5, p.peerConn.Addr(), sp.spawn, func(i int, b []byte, from netip.AddrPort) {
		ch <- got{i, string(b), from}
	})
	if err != nil {
		t.Fatal(err)
	}
	return pool
}

func TestPoolLowTTLToPeerOnly(t *testing.T) {
	checkGoroutines(t)
	p := newPoolNet(t)
	sp := &spawner{}
	pool := open(t, p, sp, 8, make(chan got, 8))
	defer sp.wg.Wait()
	defer pool.Close()
	if pool.Len() != 8 {
		t.Fatalf("Len = %d, want 8", pool.Len())
	}
	for i := range 8 {
		if err := pool.Send(i, []byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	pkts := p.packets()
	srcs := map[netip.AddrPort]bool{}
	for _, pk := range pkts {
		if pk.To != p.peerConn.Addr() || pk.TTL != 5 {
			t.Fatalf("packet to %v with TTL %d, want only %v with TTL 5", pk.To, pk.TTL, p.peerConn.Addr())
		}
		srcs[pk.From] = true
	}
	if len(pkts) != 8 || len(srcs) != 8 {
		t.Fatalf("%d packets from %d sockets, want 8 from 8", len(pkts), len(srcs))
	}
	pool.SetTTL(3, 64)
	pool.Send(3, []byte("y"))
	if pk := p.packets()[8]; pk.TTL != 64 {
		t.Fatalf("TTL %d after SetTTL(64)", pk.TTL)
	}
	if err := pool.Send(8, nil); err == nil {
		t.Fatal("Send to a holder out of range succeeded")
	}
}

func TestPoolHandlesOnlyPeer(t *testing.T) {
	checkGoroutines(t)
	p := newPoolNet(t)
	sp := &spawner{}
	ch := make(chan got, 8)
	pool := open(t, p, sp, 3, ch)
	defer sp.wg.Wait()
	defer pool.Close()
	other, err := p.peer.ListenUDP(7001)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	stranger, _ := p.net.AddHost(netip.MustParseAddr("198.18.2.1"))
	sc, _ := stranger.ListenUDP(7000)
	defer sc.Close()
	for i := range 3 {
		to := net.UDPAddrFromAddrPort(p.holderAddr(t, pool, i))
		other.WriteTo([]byte("same host, other port"), to)
		sc.WriteTo([]byte("other host"), to)
		p.peerConn.WriteTo([]byte("peer"), to)
	}
	seen := map[int]bool{}
	for range 3 {
		select {
		case g := <-ch:
			if g.b != "peer" || g.from != p.peerConn.Addr() || seen[g.i] {
				t.Fatalf("handled %+v", g)
			}
			seen[g.i] = true
		case <-time.After(2 * time.Second):
			t.Fatal("peer's packet not handled")
		}
	}
	select {
	case g := <-ch:
		t.Fatalf("handled %+v", g)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestPoolClose(t *testing.T) {
	checkGoroutines(t)
	p := newPoolNet(t)
	sp := &spawner{}
	pool := open(t, p, sp, 16, make(chan got, 1))
	addrs := make([]netip.AddrPort, 16)
	for i := range addrs {
		addrs[i] = p.holderAddr(t, pool, i)
	}
	if n := pool.Close(); n != 16 {
		t.Fatalf("Close closed %d, want 16", n)
	}
	// A reader is done once its loop has returned; the spawner counts it a moment later.
	for i, x := range pool.holders {
		select {
		case <-x.done:
		default:
			t.Fatalf("reader %d still running when Close returned", i)
		}
	}
	if n := pool.Close(); n != 0 {
		t.Fatalf("second Close closed %d", n)
	}
	sp.wg.Wait()
	for _, a := range addrs {
		c, err := p.local.ListenUDP(a.Port())
		if err != nil {
			t.Fatalf("port %d still open after Close: %v", a.Port(), err)
		}
		c.Close()
	}
	if err := pool.Send(0, []byte("x")); err == nil {
		t.Fatal("Send after Close succeeded")
	}
}

func TestPoolTake(t *testing.T) {
	checkGoroutines(t)
	p := newPoolNet(t)
	sp := &spawner{}
	ch := make(chan got, 4)
	pool := open(t, p, sp, 4, ch)
	pc, err := pool.Take(2)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	if _, err := pool.Take(2); err == nil {
		t.Fatal("Take twice succeeded")
	}
	if r := sp.running.Load(); r != 3 {
		t.Fatalf("%d readers running after Take, want 3", r)
	}
	if n := pool.Close(); n != 3 {
		t.Fatalf("Close closed %d, want 3 besides the taken one", n)
	}
	sp.wg.Wait()
	// The taken socket is open, has no reader left, no deadline, and is back at the default TTL.
	go func() {
		time.Sleep(50 * time.Millisecond)
		p.peerConn.WriteTo([]byte("after take"), pc.LocalAddr())
	}()
	buf := make([]byte, 64)
	k, _, err := pc.ReadFrom(buf)
	if err != nil || string(buf[:k]) != "after take" {
		t.Fatalf("ReadFrom on the taken socket: %q, %v", buf[:k], err)
	}
	pc.WriteTo([]byte("z"), net.UDPAddrFromAddrPort(p.peerConn.Addr()))
	pkts := p.packets()
	if last := pkts[len(pkts)-1]; last.TTL != netsim.DefaultTTL {
		t.Fatalf("taken socket sends with TTL %d", last.TTL)
	}
	select {
	case g := <-ch:
		t.Fatalf("handler ran after Take: %+v", g)
	default:
	}
}

func TestPoolOpenFails(t *testing.T) {
	checkGoroutines(t)
	p := newPoolNet(t)
	sp := &spawner{}
	var opened []net.PacketConn
	errFull := errors.New("too many open files")
	listen := func() (net.PacketConn, error) {
		if len(opened) == 3 {
			return nil, errFull
		}
		c, err := p.listen()
		if err == nil {
			opened = append(opened, c)
		}
		return c, err
	}
	if _, err := Open(8, listen, 5, p.peerConn.Addr(), sp.spawn, func(int, []byte, netip.AddrPort) {}); !errors.Is(err, errFull) {
		t.Fatalf("Open: %v, want the listen error", err)
	}
	sp.wg.Wait()
	for _, c := range opened {
		if _, err := c.WriteTo([]byte("x"), net.UDPAddrFromAddrPort(p.peerConn.Addr())); err == nil {
			t.Fatal("a socket opened before the failure is still open")
		}
	}
	sp.closed = true
	opened = nil
	if _, err := Open(2, listen, 5, p.peerConn.Addr(), sp.spawn, func(int, []byte, netip.AddrPort) {}); !errors.Is(err, ErrClosed) {
		t.Fatalf("Open on a closed node: %v, want ErrClosed", err)
	}
	for _, c := range opened {
		if _, err := c.WriteTo([]byte("x"), net.UDPAddrFromAddrPort(p.peerConn.Addr())); err == nil {
			t.Fatal("a socket is open after a refused spawn")
		}
	}
}

func TestSetTTLLoopback(t *testing.T) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := SetTTL(c, 5); err != nil {
		t.Fatal(err)
	}
	if ttl, err := ttlOf(c); err != nil || ttl != 5 {
		t.Fatalf("TTL %d, %v, want 5", ttl, err)
	}
	if err := SetTTL(c, 64); err != nil {
		t.Fatal(err)
	}
	if ttl, _ := ttlOf(c); ttl != 64 {
		t.Fatalf("TTL %d, want 64", ttl)
	}
}

func ttlOf(c *net.UDPConn) (int, error) { return ipv4.NewPacketConn(c).TTL() }

// TestPoolIPv4Only refuses a peer that is not IPv4, IPv4-mapped included, before opening any socket.
func TestPoolIPv4Only(t *testing.T) {
	checkGoroutines(t)
	p := newPoolNet(t)
	sp := &spawner{}
	peer := p.peerConn.Addr()
	opened := 0
	listen := func() (net.PacketConn, error) {
		opened++
		return p.listen()
	}
	for _, a := range []netip.AddrPort{netip.AddrPortFrom(netip.AddrFrom16(peer.Addr().As16()), peer.Port()), netip.MustParseAddrPort("[2001:db8::1]:7000")} {
		if pool, err := Open(2, listen, 5, a, sp.spawn, func(int, []byte, netip.AddrPort) {}); err == nil {
			pool.Close()
			t.Errorf("Open toward %v succeeded", a)
		}
	}
	sp.wg.Wait()
	if opened != 0 {
		t.Fatalf("%d sockets opened", opened)
	}
}

// sixteen reports senders in the 16-byte form an OS may use for an IPv4 address.
type sixteen struct{ *netsim.Conn }

func (s sixteen) ReadFrom(b []byte) (int, net.Addr, error) {
	n, a, err := s.Conn.ReadFrom(b)
	if ua, ok := a.(*net.UDPAddr); ok {
		a = &net.UDPAddr{IP: ua.IP.To16(), Port: ua.Port}
	}
	return n, a, err
}

// TestPoolOSAddrForm matches the peer when the socket reports it in 16 bytes, and hands it on as IPv4.
func TestPoolOSAddrForm(t *testing.T) {
	checkGoroutines(t)
	p := newPoolNet(t)
	sp := &spawner{}
	ch := make(chan got, 1)
	listen := func() (net.PacketConn, error) {
		c, err := p.local.ListenUDP(0)
		return sixteen{c}, err
	}
	pool, err := Open(1, listen, 5, p.peerConn.Addr(), sp.spawn, func(i int, b []byte, from netip.AddrPort) {
		ch <- got{i, string(b), from}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sp.wg.Wait()
	defer pool.Close()
	p.peerConn.WriteTo([]byte("peer"), net.UDPAddrFromAddrPort(p.holderAddr(t, pool, 0)))
	select {
	case g := <-ch:
		if g.from != p.peerConn.Addr() || !g.from.Addr().Is4() {
			t.Fatalf("handled from %v", g.from)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("peer's packet not handled")
	}
}
