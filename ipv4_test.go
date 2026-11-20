package kolodht

// Tests that v0.1.x is IPv4 only: every IPv6 address a caller passes, IPv4-mapped ones included, is refused with
// ErrInvalidArgument.

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/ciranda-dev/kolo-dht/internal/wire"
)

var ipv6Inputs = []string{"::1", "::", "fe80::1", "2001:db8::1", "64:ff9b::7f00:1", "2002:7f00:1::1", "::ffff:127.0.0.1"}

// mapped returns ap in its IPv4-mapped IPv6 form.
func mapped(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom16(ap.Addr().As16()), ap.Port())
}

// TestLoopbackConsistent bootstraps nodes with no NAT from three servers on 127.0.0.1: each is classified consistent,
// and two of them connect.
func TestLoopbackConsistent(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t, 20*time.Second)
	var servers []netip.AddrPort
	for i := range 3 {
		// Servers on one IP that never meet keep their random r: one r for all three gives each client one entry, maybe not
		// the same one, and Lookup then misses the record.
		s := loopNode(t, fastConfig(true))
		s.mu.Lock()
		s.r.Store(uint32(i))
		s.table.SetSelf(s.selfID())
		s.mu.Unlock()
		servers = append(servers, addrOf(s))
	}
	a, b := loopNode(t, fastConfig(false)), loopNode(t, fastConfig(false))
	for _, n := range []*Node{a, b} {
		if err := n.Bootstrap(ctx, servers); err != nil {
			t.Fatal(err)
		}
		n.mu.Lock()
		c, k := n.nat.class(time.Now()), len(n.nat.samples)
		n.mu.Unlock()
		if c != wire.ClassConsistent {
			t.Fatalf("class %v from %d samples, want consistent", c, k)
		}
	}
	if err := connectPair(t, ctx, a, b, topicOf("loopback-consistent")); err != nil {
		t.Fatal(err)
	}
}

func TestNewRefusesIPv6(t *testing.T) {
	checkGoroutines(t)
	ctx := context.Background()
	for _, ip := range append(ipv6Inputs, "fe80::1%lo0") {
		addr := "[" + ip + "]:0"
		n, err := New(ctx, addr, ident(t), nil)
		if n != nil {
			n.Close()
		}
		if !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("New(%s): %v, want ErrInvalidArgument", addr, err)
		}
	}
	n, err := New(ctx, "127.0.0.1:0", ident(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	if a := addrOf(n); !a.Addr().Is4() || !a.Addr().IsLoopback() {
		t.Fatalf("IPv4 listen address gave %s", a)
	}
}

func TestBootstrapRefusesIPv6(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t, 10*time.Second)
	s := loopNode(t, fastConfig(true))
	n := loopNode(t, fastConfig(false))
	for _, ip := range ipv6Inputs {
		v6 := netip.AddrPortFrom(netip.MustParseAddr(ip), 4000)
		if err := n.Bootstrap(ctx, []netip.AddrPort{addrOf(s), v6}); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("Bootstrap with %s: %v, want ErrInvalidArgument", v6, err)
		}
	}
	if err := n.Bootstrap(ctx, []netip.AddrPort{mapped(addrOf(s))}); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("Bootstrap with the server's IPv4-mapped address: %v, want ErrInvalidArgument", err)
	}
	time.Sleep(wait)
	if got := s.Stats().Requests; got != 0 {
		t.Fatalf("a refused Bootstrap sent %d requests", got)
	}
	if err := n.Bootstrap(ctx, []netip.AddrPort{addrOf(s)}); err != nil {
		t.Fatalf("Bootstrap with the IPv4 address: %v", err)
	}
}

func TestConnectRefusesIPv6(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t, 10*time.Second)
	s := loopNode(t, fastConfig(true))
	a, b := loopNode(t, fastConfig(false)), loopNode(t, fastConfig(false))
	for _, n := range []*Node{a, b} {
		if err := n.Bootstrap(ctx, []netip.AddrPort{addrOf(s)}); err != nil {
			t.Fatal(err)
		}
	}
	topic := topicOf("connect-ipv6")
	if err := b.Announce(ctx, topic); err != nil {
		t.Fatal(err)
	}
	recs, err := a.Lookup(ctx, topic)
	if err != nil || len(recs) != 1 {
		t.Fatalf("Lookup = %+v, %v", recs, err)
	}
	before := s.Stats().Requests
	for _, ip := range append(ipv6Inputs, mapped(recs[0].Addr).Addr().String()) {
		r := recs[0]
		r.Addr = netip.AddrPortFrom(netip.MustParseAddr(ip), recs[0].Addr.Port())
		if c, err := a.Connect(ctx, r); !errors.Is(err, ErrInvalidArgument) {
			if c != nil {
				c.Close()
			}
			t.Errorf("Connect to %s: %v, want ErrInvalidArgument", r.Addr, err)
		}
	}
	if got := s.Stats().Requests - before; got != 0 {
		t.Fatalf("a refused Connect sent %d requests", got)
	}
}

// sixteen is a loopback IPv4 socket that reports addresses as 16-byte net.IP values, as an OS may.
type sixteen struct{ pc *net.UDPConn }

func to16(a net.Addr) net.Addr {
	if ua, ok := a.(*net.UDPAddr); ok {
		return &net.UDPAddr{IP: ua.IP.To16(), Port: ua.Port}
	}
	return a
}

func (s sixteen) ReadFrom(b []byte) (int, net.Addr, error) {
	n, a, err := s.pc.ReadFrom(b)
	return n, to16(a), err
}
func (s sixteen) WriteTo(b []byte, a net.Addr) (int, error) { return s.pc.WriteTo(b, a) }
func (s sixteen) Close() error                              { return s.pc.Close() }
func (s sixteen) LocalAddr() net.Addr                       { return to16(s.pc.LocalAddr()) }
func (s sixteen) SetDeadline(t time.Time) error             { return s.pc.SetDeadline(t) }
func (s sixteen) SetReadDeadline(t time.Time) error         { return s.pc.SetReadDeadline(t) }
func (s sixteen) SetWriteDeadline(t time.Time) error        { return s.pc.SetWriteDeadline(t) }

// TestOSMappedAddrs checks that IPv4 addresses the OS reports in 16-byte form are used as IPv4 inside a node, so
// loopback traffic on such a socket works: it bootstraps, announces and is found at an IPv4 address.
func TestOSMappedAddrs(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t, 10*time.Second)
	s := loopNode(t, fastConfig(true))
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	n, err := newConn(context.Background(), sixteen{pc}, nil, ident(t), fastConfig(false), defaultTiming, -1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Close() })
	n.mu.Lock()
	local, self := n.local, n.selfIP
	n.mu.Unlock()
	if !local.Addr().Is4() || !self.Is4() {
		t.Fatalf("local address %s, own IP %s, want IPv4", local, self)
	}
	other := loopNode(t, fastConfig(false))
	for _, x := range []*Node{n, other} {
		if err := x.Bootstrap(ctx, []netip.AddrPort{addrOf(s)}); err != nil {
			t.Fatal(err)
		}
	}
	topic := topicOf("os-mapped")
	if err := n.Announce(ctx, topic); err != nil {
		t.Fatal(err)
	}
	recs, err := other.Lookup(ctx, topic)
	if err != nil || len(recs) != 1 || !recs[0].Addr.Addr().Is4() {
		t.Fatalf("Lookup = %+v, %v", recs, err)
	}
}

// TestIPv6SourceDropped checks that a datagram from an IPv6 source, IPv4-mapped included, is dropped before the rate
// limits and the decoder.
func TestIPv6SourceDropped(t *testing.T) {
	checkGoroutines(t)
	n := loopNode(t, fastConfig(true))
	b, err := wire.Encode(1, &wire.Ping{Flags: wire.NewFlags(0, true)}, pingSize)
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range ipv6Inputs {
		n.handlePacket(b, netip.AddrPortFrom(netip.MustParseAddr(ip), 4000), time.Now())
	}
	if st := n.Stats(); st.Requests != 0 || st.Limited != 0 {
		t.Fatalf("IPv6 sources counted: %+v", st)
	}
	n.handlePacket(b, netip.MustParseAddrPort("127.0.0.1:4000"), time.Now())
	if st := n.Stats(); st.Requests != 1 {
		t.Fatalf("IPv4 source not counted: %+v", st)
	}
}
