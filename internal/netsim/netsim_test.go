package netsim

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"testing"
	"time"
)

func TestPublicDelivery(t *testing.T) {
	n := New(Config{})
	a := listen(t, publicHost(t, n, "203.0.113.1"), 4000)
	b := listen(t, publicHost(t, n, "203.0.113.2"), 0)
	if a.Addr() != netip.MustParseAddrPort("203.0.113.1:4000") {
		t.Fatalf("Addr = %s", a.Addr())
	}
	if got := a.LocalAddr().(*net.UDPAddr).AddrPort(); got != a.Addr() {
		t.Fatalf("LocalAddr = %s", got)
	}
	send(t, b, a.Addr(), "ping")
	msg, from, ok := recv(t, a, time.Second)
	if !ok || msg != "ping" || from != b.Addr() {
		t.Fatalf("got %q from %s, %v", msg, from, ok)
	}
	send(t, b, netip.MustParseAddrPort("203.0.113.1:4001"), "lost")
	send(t, b, netip.MustParseAddrPort("192.0.2.99:1"), "lost")
	if _, _, ok := recv(t, a, short); ok {
		t.Fatal("packet to a closed port delivered")
	}
	send(t, b, a.Addr(), "abcdef")
	buf := make([]byte, 3)
	nr, _, err := a.ReadFrom(buf)
	if err != nil || nr != 3 || string(buf) != "abc" {
		t.Fatalf("truncated read: %d %q %v", nr, buf, err)
	}
}

func TestListenErrors(t *testing.T) {
	n := New(Config{})
	h := publicHost(t, n, "203.0.113.1")
	listen(t, h, 4000)
	if _, err := h.ListenUDP(4000); err == nil {
		t.Fatal("second listener on one port")
	}
	x, y := listen(t, h, 0), listen(t, h, 0)
	if x.Addr().Port() == 0 || x.Addr() == y.Addr() {
		t.Fatalf("ephemeral ports %s and %s", x.Addr(), y.Addr())
	}
	if _, err := n.AddHost(ip("203.0.113.1")); err == nil {
		t.Fatal("duplicate host")
	}
	if _, err := n.AddNAT(ip("203.0.113.1"), NATConfig{}); err == nil {
		t.Fatal("NAT on a host address")
	}
	nat, _ := natHost(t, n, "198.51.100.1", "10.0.0.1", NATConfig{})
	if _, err := nat.AddHost(ip("10.0.0.1")); err == nil {
		t.Fatal("duplicate private host")
	}
	if _, err := n.AddHost(ip("198.51.100.1")); err == nil {
		t.Fatal("host on a NAT address")
	}
	// The network is IPv4 only, and an IPv4-mapped netip.Addr is IPv6.
	if _, err := n.AddHost(ip("2001:db8::1")); err == nil {
		t.Fatal("IPv6 host")
	}
	if _, err := n.AddNAT(ip("2001:db8::2"), NATConfig{}); err == nil {
		t.Fatal("IPv6 NAT")
	}
	if _, err := nat.AddHost(ip("fd00::2")); err == nil {
		t.Fatal("IPv6 private host")
	}
	if _, err := x.WriteTo([]byte("x"), &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 1}); err == nil {
		t.Fatal("write to an IPv6 address")
	}
	if _, err := n.AddHost(ip("::ffff:203.0.113.9")); err == nil {
		t.Fatal("IPv4-mapped host")
	}
	if _, err := n.AddNAT(ip("::ffff:203.0.113.10"), NATConfig{}); err == nil {
		t.Fatal("IPv4-mapped NAT")
	}
	if _, err := nat.AddHost(ip("::ffff:10.0.0.3")); err == nil {
		t.Fatal("IPv4-mapped private host")
	}
}

func TestConnSemantics(t *testing.T) {
	checkGoroutines(t)
	n := New(Config{})
	h := publicHost(t, n, "203.0.113.1")
	c, err := h.ListenUDP(0)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.SetReadBuffer(1 << 20); err != nil {
		t.Fatal(err)
	}
	if err := c.SetWriteBuffer(1 << 20); err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(-time.Second))
	if _, _, err := c.ReadFrom(make([]byte, 10)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("past deadline: %v", err)
	}
	c.SetReadDeadline(time.Time{})
	done := make(chan error, 1)
	go func() {
		_, _, err := c.ReadFrom(make([]byte, 10))
		done <- err
	}()
	time.Sleep(short)
	c.SetDeadline(time.Now().Add(short))
	if err := <-done; !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("changed deadline: %v", err)
	}
	c.SetReadDeadline(time.Time{})
	go func() {
		_, _, err := c.ReadFrom(make([]byte, 10))
		done <- err
	}()
	time.Sleep(short)
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("read after Close: %v", err)
	}
	if _, err := c.WriteTo([]byte("x"), net.UDPAddrFromAddrPort(c.Addr())); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("write after Close: %v", err)
	}
	if err := c.Close(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("second Close: %v", err)
	}
	c2 := listen(t, h, c.Addr().Port())
	if _, err := c2.WriteTo([]byte("x"), &net.IPAddr{IP: net.IPv4(1, 2, 3, 4)}); err == nil {
		t.Fatal("WriteTo accepted a non-UDP address")
	}
}

func TestQueueBound(t *testing.T) {
	n := New(Config{QueueLen: 8})
	a := listen(t, publicHost(t, n, "203.0.113.1"), 0)
	b := listen(t, publicHost(t, n, "203.0.113.2"), 0)
	for i := range 20 {
		send(t, b, a.Addr(), fmt.Sprint(i))
	}
	got := 0
	for {
		if _, _, ok := recv(t, a, short); !ok {
			break
		}
		got++
	}
	if got != 8 {
		t.Fatalf("received %d, want the queue length 8", got)
	}
}

func TestLatencyAndLoss(t *testing.T) {
	checkGoroutines(t)
	n := New(Config{Latency: 50 * time.Millisecond})
	a := listen(t, publicHost(t, n, "203.0.113.1"), 0)
	b := listen(t, publicHost(t, n, "203.0.113.2"), 0)
	start := time.Now()
	send(t, b, a.Addr(), "x")
	if _, _, ok := recv(t, a, time.Second); !ok {
		t.Fatal("not delivered")
	}
	if d := time.Since(start); d < 50*time.Millisecond {
		t.Fatalf("delivered after %v, before the latency", d)
	}

	lossy := New(Config{Loss: 1})
	a = listen(t, publicHost(t, lossy, "203.0.113.1"), 0)
	b = listen(t, publicHost(t, lossy, "203.0.113.2"), 0)
	for range 10 {
		send(t, b, a.Addr(), "x")
	}
	if _, _, ok := recv(t, a, short); ok {
		t.Fatal("delivered with Loss 1")
	}
}

// servers returns two sockets on S1 and one on S2, all public.
func servers(t *testing.T, n *Network) (s1a, s1b, s2 *Conn) {
	h1 := publicHost(t, n, "203.0.113.1")
	return listen(t, h1, 1000), listen(t, h1, 2000), listen(t, publicHost(t, n, "203.0.113.2"), 1000)
}

func TestMapping(t *testing.T) {
	for _, tt := range []struct {
		m                  Mapping
		samePort, sameAddr bool // S1:1000 vs S1:2000, S1 vs S2
	}{
		{EndpointIndependent, true, true},
		{AddressDependent, true, false},
		{AddressPortDependent, false, false},
	} {
		t.Run(tt.m.String(), func(t *testing.T) {
			n := New(Config{Seed: 1})
			s1a, s1b, s2 := servers(t, n)
			_, h := natHost(t, n, "198.51.100.1", "10.0.0.2", NATConfig{Mapping: tt.m})
			c := listen(t, h, 5000)
			x, y, z := observed(t, c, s1a), observed(t, c, s1b), observed(t, c, s2)
			if x.Addr() != ip("198.51.100.1") || y.Addr() != x.Addr() || z.Addr() != x.Addr() {
				t.Fatalf("external IPs %s %s %s", x, y, z)
			}
			if (x == y) != tt.samePort || (x == z) != tt.sameAddr || (y == z) != tt.sameAddr {
				t.Fatalf("mappings %s %s %s", x, y, z)
			}
			// The same destination keeps its mapping (REQ-1 for EIM, and the definition for the others).
			if again := observed(t, c, s1a); again != x {
				t.Fatalf("second packet to S1 used %s, first %s", again, x)
			}
		})
	}
}

func TestFiltering(t *testing.T) {
	for _, tt := range []struct {
		f                Filtering
		fromPort, fromIP bool // S1:2000 and S2 may reach a mapping opened toward S1:1000
	}{
		{EndpointIndependentFiltering, true, true},
		{AddressDependentFiltering, true, false},
		{AddressPortDependentFiltering, false, false},
	} {
		t.Run(tt.f.String(), func(t *testing.T) {
			n := New(Config{})
			s1a, s1b, s2 := servers(t, n)
			_, h := natHost(t, n, "198.51.100.1", "10.0.0.2", NATConfig{Filtering: tt.f})
			c := listen(t, h, 5000)
			send(t, s1a, netip.MustParseAddrPort("198.51.100.1:5000"), "x")
			if _, _, ok := recv(t, c, short); ok {
				t.Fatal("unsolicited packet delivered without a mapping")
			}
			ext := observed(t, c, s1a)
			for _, s := range []struct {
				c    *Conn
				want bool
			}{{s1a, true}, {s1b, tt.fromPort}, {s2, tt.fromIP}} {
				send(t, s.c, ext, "in")
				msg, from, ok := recv(t, c, short)
				if ok != s.want {
					t.Fatalf("from %s: delivered %v, want %v", s.c.Addr(), ok, s.want)
				}
				if ok && (msg != "in" || from != s.c.Addr()) {
					t.Fatalf("from %s: got %q from %s", s.c.Addr(), msg, from)
				}
			}
		})
	}
}

func TestPortAssignment(t *testing.T) {
	n := New(Config{Seed: 7})
	s1, _, _ := servers(t, n)
	_, h := natHost(t, n, "198.51.100.1", "10.0.0.2", NATConfig{PreservePort: true})
	if got := observed(t, listen(t, h, 5000), s1); got.Port() != 5000 {
		t.Fatalf("preserved port %d", got.Port())
	}
	_, h2 := natHost(t, n, "198.51.100.2", "10.0.0.2", NATConfig{})
	got := observed(t, listen(t, h2, 5000), s1)
	if got.Port() < 1024 {
		t.Fatalf("assigned port %d below 1024", got.Port())
	}
	// Two private hosts with the same port get different external ports when preserving.
	nat, h3 := natHost(t, n, "198.51.100.3", "10.0.0.2", NATConfig{PreservePort: true})
	h4, err := nat.AddHost(ip("10.0.0.3"))
	if err != nil {
		t.Fatal(err)
	}
	p, q := observed(t, listen(t, h3, 6000), s1), observed(t, listen(t, h4, 6000), s1)
	if p == q {
		t.Fatalf("two hosts share external %s", p)
	}
}

func TestMappingTimer(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clk := &clock{now: t0}
	n := New(Config{Now: clk.Now, Seed: 3})
	s1a, s1b, s2 := servers(t, n)

	// With endpoint-independent filtering only the mapping timer can drop a packet.
	_, eh := natHost(t, n, "198.51.100.2", "10.0.0.2", NATConfig{Timeout: 30 * time.Second})
	ec := listen(t, eh, 5000)
	eext := observed(t, ec, s1a)
	for _, at := range []time.Duration{10 * time.Second, 20 * time.Second, 29 * time.Second} {
		clk.Set(t0.Add(at))
		send(t, s1b, eext, "in")
		if _, _, ok := recv(t, ec, short); !ok {
			t.Fatalf("dropped at %v, before the timer", at)
		}
	}
	// Inbound packets do not refresh (REQ-6): the mapping expires 30s after the last outbound one.
	clk.Set(t0.Add(30 * time.Second))
	send(t, s1b, eext, "in")
	if _, _, ok := recv(t, ec, short); ok {
		t.Fatal("delivered at the timer although only inbound traffic refreshed it")
	}

	clk.Set(t0)
	_, h := natHost(t, n, "198.51.100.1", "10.0.0.2", NATConfig{Filtering: AddressPortDependentFiltering, Timeout: 30 * time.Second})
	c := listen(t, h, 5000)
	ext := observed(t, c, s1a)

	deliver := func(from *Conn, at time.Duration) bool {
		t.Helper()
		clk.Set(t0.Add(at))
		send(t, from, ext, "in")
		_, _, ok := recv(t, c, short)
		return ok
	}
	if !deliver(s1a, 29*time.Second) {
		t.Fatal("dropped before the timer")
	}
	if deliver(s1a, 30*time.Second) {
		t.Fatal("delivered at the timer")
	}

	// Outbound traffic refreshes; each destination's filter has its own timer.
	clk.Set(t0.Add(time.Minute))
	ext = observed(t, c, s1a)
	clk.Set(t0.Add(time.Minute + 20*time.Second))
	if got := observed(t, c, s2); got != ext {
		t.Fatalf("EIM gave %s to S2 and %s to S1", got, ext)
	}
	if !deliver(s2, time.Minute+45*time.Second) {
		t.Fatal("S2 dropped although refreshed 25s ago")
	}
	if deliver(s1a, time.Minute+45*time.Second) {
		t.Fatal("S1 delivered 45s after its last outbound packet")
	}
}

func TestHairpin(t *testing.T) {
	for _, hairpin := range []bool{false, true} {
		t.Run(fmt.Sprint(hairpin), func(t *testing.T) {
			n := New(Config{})
			s1, _, _ := servers(t, n)
			nat, ha := natHost(t, n, "198.51.100.1", "10.0.0.2", NATConfig{Filtering: EndpointIndependentFiltering, Hairpin: hairpin})
			hb, err := nat.AddHost(ip("10.0.0.3"))
			if err != nil {
				t.Fatal(err)
			}
			a, b := listen(t, ha, 5000), listen(t, hb, 5000)
			extA, extB := observed(t, a, s1), observed(t, b, s1)
			send(t, a, extB, "hairpin")
			msg, from, ok := recv(t, b, short)
			if ok != hairpin {
				t.Fatalf("hairpin delivered %v", ok)
			}
			if ok && (msg != "hairpin" || from != extA) {
				t.Fatalf("got %q from %s, want from %s (REQ-9a)", msg, from, extA)
			}
			send(t, a, b.Addr(), "lan")
			if msg, from, ok := recv(t, b, short); !ok || msg != "lan" || from != a.Addr() {
				t.Fatalf("LAN: %q from %s, %v", msg, from, ok)
			}
		})
	}
}

func TestBlocked(t *testing.T) {
	n := New(Config{})
	s1, _, _ := servers(t, n)
	_, h := natHost(t, n, "198.51.100.1", "10.0.0.2", NATConfig{Blocked: true})
	c := listen(t, h, 5000)
	send(t, c, s1.Addr(), "out")
	if _, _, ok := recv(t, s1, short); ok {
		t.Fatal("blocked NAT let a packet out")
	}
	send(t, s1, netip.MustParseAddrPort("198.51.100.1:5000"), "in")
	if _, _, ok := recv(t, c, short); ok {
		t.Fatal("blocked NAT let a packet in")
	}
}

// natKind is one row or column of the hole punching table in docs/protocol.md.
type natKind struct {
	name   string
	public bool
	cfg    NATConfig
}

var kinds = []natKind{
	{"public", true, NATConfig{}},
	{"full-cone", false, NATConfig{Mapping: EndpointIndependent, Filtering: EndpointIndependentFiltering}},
	{"restricted", false, NATConfig{Mapping: EndpointIndependent, Filtering: AddressDependentFiltering}},
	{"port-restricted", false, NATConfig{Mapping: EndpointIndependent, Filtering: AddressPortDependentFiltering}},
	{"symmetric", false, NATConfig{Mapping: AddressPortDependent, Filtering: AddressPortDependentFiltering}},
	{"address-dependent", false, NATConfig{Mapping: AddressDependent, Filtering: AddressDependentFiltering}},
}

// punchWorks is the expected outcome of that table, indexed by kind name.
func punchWorks(a, b string) bool {
	random := func(k string) bool { return k == "symmetric" || k == "address-dependent" }
	switch {
	case random(a) && random(b):
		return false
	case random(b):
		return a != "port-restricted"
	case random(a):
		return b != "port-restricted"
	}
	return true
}

// TestHolePunchPackets runs the punch order with raw packets: the waiting side probes the dialer's address as the
// rendezvous server saw it, and the side with an address-dependent mapping dials.
func TestHolePunchPackets(t *testing.T) {
	for i, ka := range kinds {
		for j, kb := range kinds {
			t.Run(ka.name+"/"+kb.name, func(t *testing.T) {
				n := New(Config{Seed: uint64(i*10 + j)})
				s := listen(t, publicHost(t, n, "203.0.113.1"), 1000)
				peer := func(k natKind, public, private string) *Conn {
					if k.public {
						return listen(t, publicHost(t, n, public), 5000)
					}
					_, h := natHost(t, n, public, private, k.cfg)
					return listen(t, h, 5000)
				}
				a := peer(ka, "198.51.100.1", "10.0.0.2")
				b := peer(kb, "192.0.2.1", "10.0.0.2")
				aS, bS := observed(t, a, s), observed(t, b, s)

				dialer, waiter, dialerS, waiterS := a, b, aS, bS
				if kb.cfg.Mapping != EndpointIndependent && !kb.public && (ka.public || ka.cfg.Mapping == EndpointIndependent) {
					dialer, waiter, dialerS, waiterS = b, a, bS, aS
				}
				send(t, waiter, dialerS, "probe")
				recv(t, dialer, short) // a probe that arrives is ignored
				send(t, dialer, waiterS, "initial")
				got := false
				if msg, from, ok := recv(t, waiter, short); ok && msg == "initial" {
					send(t, waiter, from, "reply")
					msg, _, ok := recv(t, dialer, short)
					got = ok && msg == "reply"
				}
				if want := punchWorks(ka.name, kb.name); got != want {
					t.Fatalf("punch %s to %s: %v, want %v", ka.name, kb.name, got, want)
				}
			})
		}
	}
}

func TestInject(t *testing.T) {
	n := New(Config{})
	s1, _, _ := servers(t, n)
	_, h := natHost(t, n, "198.51.100.1", "10.0.0.2", NATConfig{Filtering: AddressPortDependentFiltering})
	c := listen(t, h, 5000)
	ext := observed(t, c, s1)
	spoofed := netip.MustParseAddrPort("192.0.2.200:7")
	// A forged source goes through the NAT filter like any other.
	n.Inject(spoofed, ext, []byte("forged"))
	if _, _, ok := recv(t, c, short); ok {
		t.Fatal("forged packet passed the filter")
	}
	n.Inject(s1.Addr(), ext, []byte("as s1"))
	if msg, from, ok := recv(t, c, short); !ok || msg != "as s1" || from != s1.Addr() {
		t.Fatalf("got %q from %s, %v", msg, from, ok)
	}
	n.Inject(spoofed, s1.Addr(), []byte("to public"))
	if msg, from, ok := recv(t, s1, short); !ok || msg != "to public" || from != spoofed {
		t.Fatalf("public: %q from %s, %v", msg, from, ok)
	}
}

func sendTTL(t *testing.T, c *Conn, ttl int, to netip.AddrPort, msg string) {
	t.Helper()
	if err := c.SetTTL(ttl); err != nil {
		t.Fatal(err)
	}
	send(t, c, to, msg)
}

// TestTTL checks the hop count: each NAT is one router and Hops routers sit between any two boxes, so a TTL-5 packet
// opens the sender's NAT mapping and dies before the remote NAT, and a TTL-1 packet dies in the sender's NAT.
func TestTTL(t *testing.T) {
	n := New(Config{Seed: 1})
	s, _, _ := servers(t, n)
	_, ha := natHost(t, n, "198.51.100.1", "10.0.0.2", NATConfig{Filtering: AddressPortDependentFiltering})
	_, hb := natHost(t, n, "192.0.2.1", "10.0.0.2", NATConfig{Filtering: AddressPortDependentFiltering})
	a, b := listen(t, ha, 5000), listen(t, hb, 5000)
	aExt, bExt := observed(t, a, s), observed(t, b, s)

	for _, ttl := range []int{0, -1, 256} {
		if err := a.SetTTL(ttl); err == nil {
			t.Fatalf("SetTTL(%d) accepted", ttl)
		}
	}
	// TTL 5: a's NAT maps and opens its filter toward b, b's NAT never sees it.
	sendTTL(t, a, 5, bExt, "low")
	if _, _, ok := recv(t, b, short); ok {
		t.Fatal("TTL-5 packet crossed both NATs")
	}
	sendTTL(t, b, 64, aExt, "in")
	if msg, from, ok := recv(t, a, short); !ok || msg != "in" || from != bExt {
		t.Fatalf("after a TTL-5 packet, b to a: %q from %s, %v", msg, from, ok)
	}
	// TTL 1 dies in the NAT itself, before any mapping.
	c := listen(t, ha, 5001)
	sendTTL(t, c, 1, bExt, "dead")
	cExt := netip.AddrPortFrom(aExt.Addr(), 5001)
	for p := uint16(1024); p < 1100; p++ {
		send(t, b, netip.AddrPortFrom(cExt.Addr(), p), "scan")
	}
	if _, _, ok := recv(t, c, short); ok {
		t.Fatal("a TTL-1 packet created a mapping")
	}
	// Between public hosts, TTL must exceed Hops (8 by default).
	p1, p2 := listen(t, publicHost(t, n, "203.0.113.10"), 1), listen(t, publicHost(t, n, "203.0.113.11"), 1)
	sendTTL(t, p1, 8, p2.Addr(), "short")
	if _, _, ok := recv(t, p2, short); ok {
		t.Fatal("TTL 8 crossed 8 routers")
	}
	sendTTL(t, p1, 9, p2.Addr(), "long")
	if msg, _, ok := recv(t, p2, short); !ok || msg != "long" {
		t.Fatalf("TTL 9: %q %v", msg, ok)
	}
	n2 := New(Config{Hops: 2})
	q1, q2 := listen(t, publicHost(t, n2, "203.0.113.1"), 1), listen(t, publicHost(t, n2, "203.0.113.2"), 1)
	sendTTL(t, q1, 3, q2.Addr(), "hops")
	if _, _, ok := recv(t, q2, short); !ok {
		t.Fatal("TTL 3 did not cross Hops 2")
	}
}

// TestRandomPorts checks that an address and port dependent mapping takes a new random port in 1024..65535 for every
// destination.
func TestRandomPorts(t *testing.T) {
	n := New(Config{Seed: 3})
	_, h := natHost(t, n, "198.51.100.1", "10.0.0.2", NATConfig{Mapping: AddressPortDependent})
	c := listen(t, h, 5000)
	sh := publicHost(t, n, "203.0.113.1")
	seen := map[uint16]bool{}
	low, high := uint16(65535), uint16(0)
	for p := uint16(1); p <= 300; p++ {
		ext := observed(t, c, listen(t, sh, p))
		seen[ext.Port()] = true
		low, high = min(low, ext.Port()), max(high, ext.Port())
	}
	if len(seen) != 300 || low < 1024 || high-low < 50000 {
		t.Fatalf("%d distinct ports from %d to %d", len(seen), low, high)
	}
}

// TestConntrack checks the netfilter-like mapping: the internal port is kept unless another internal endpoint already
// uses it toward the same destination, and only the exact flow comes back in.
func TestConntrack(t *testing.T) {
	n := New(Config{Seed: 4})
	s1a, s1b, s2 := servers(t, n)
	nat, hx := natHost(t, n, "198.51.100.1", "10.0.0.2", NATConfig{Mapping: Conntrack})
	hy, err := nat.AddHost(ip("10.0.0.3"))
	if err != nil {
		t.Fatal(err)
	}
	x, y := listen(t, hx, 5000), listen(t, hy, 5000)
	if got := observed(t, x, s1a); got != netip.MustParseAddrPort("198.51.100.1:5000") {
		t.Fatalf("x toward s1a: %s", got)
	}
	// y collides with x toward s1a, not toward s2: its samples disagree, as a random mapping's do.
	ys1, ys2 := observed(t, y, s1a), observed(t, y, s2)
	if ys1.Port() == 5000 || ys2.Port() != 5000 {
		t.Fatalf("y toward s1a %s, toward s2 %s", ys1, ys2)
	}
	// A fresh port collides with nothing: the same external port everywhere.
	z := listen(t, hy, 0)
	for _, s := range []*Conn{s1a, s1b, s2} {
		if got := observed(t, z, s); got.Port() != z.Addr().Port() {
			t.Fatalf("z toward %s: %s", s.Addr(), got)
		}
	}
	// Only the exact flow comes back: s1b may not use x's flow toward s1a.
	send(t, s1b, netip.MustParseAddrPort("198.51.100.1:5000"), "other")
	if msg, _, ok := recv(t, x, short); ok {
		t.Fatalf("x received %q from another port of s1", msg)
	}
	send(t, s1a, netip.MustParseAddrPort("198.51.100.1:5000"), "back")
	if msg, _, ok := recv(t, x, short); !ok || msg != "back" {
		t.Fatalf("x reply: %q %v", msg, ok)
	}
	send(t, s2, netip.MustParseAddrPort("198.51.100.1:5000"), "to y")
	if msg, _, ok := recv(t, y, short); !ok || msg != "to y" {
		t.Fatalf("y reply from s2: %q %v", msg, ok)
	}
}

func TestTap(t *testing.T) {
	var mu sync.Mutex
	var got []Packet
	n := New(Config{Tap: func(p Packet) {
		mu.Lock()
		got = append(got, p)
		mu.Unlock()
	}})
	s, _, _ := servers(t, n)
	_, h := natHost(t, n, "198.51.100.1", "10.0.0.2", NATConfig{})
	c := listen(t, h, 5000)
	sendTTL(t, c, 5, s.Addr(), "low")
	sendTTL(t, c, 64, s.Addr(), "abc")
	mu.Lock()
	defer mu.Unlock()
	want := []Packet{
		{From: c.Addr(), To: s.Addr(), Size: 3, TTL: 5, Delivered: false},
		{From: c.Addr(), To: s.Addr(), Size: 3, TTL: 64, Delivered: true},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("tap saw %v, want %v", got, want)
	}
}

// TestBirthdayPackets runs a birthday punch with raw packets (256 TTL-5 sockets behind APDM, 1750 random-port probes);
// 1 - (1 - 256/64536)^1750 = 0.999.
func TestBirthdayPackets(t *testing.T) {
	const seeds = 20
	hits := 0
	for seed := range uint64(seeds) {
		n := New(Config{Seed: seed})
		_, hc := natHost(t, n, "198.51.100.1", "10.0.0.2", NATConfig{Filtering: AddressPortDependentFiltering})
		nat, hr := natHost(t, n, "192.0.2.1", "10.0.0.2", NATConfig{Mapping: AddressPortDependent, Filtering: AddressPortDependentFiltering})
		cons := listen(t, hc, 5000)
		s, _, _ := servers(t, n)
		consExt := observed(t, cons, s)
		var socks []*Conn
		for range 256 {
			r := listen(t, hr, 0)
			sendTTL(t, r, 5, consExt, "b")
			socks = append(socks, r)
		}
		rng := rand.New(rand.NewPCG(seed, 1))
		for range 1750 {
			send(t, cons, netip.AddrPortFrom(nat.Addr(), uint16(1000+rng.IntN(64536))), "p")
		}
		for _, r := range socks {
			if len(r.queue) > 0 {
				hits++
				break
			}
		}
	}
	if hits < seeds-1 {
		t.Fatalf("birthday punch reached the random side in %d of %d seeds", hits, seeds)
	}
}

// TestPorts lists the mappings that let one host in: the ones made toward it, not toward another host.
func TestPorts(t *testing.T) {
	n := New(Config{Seed: 4})
	_, h := natHost(t, n, "198.51.100.1", "10.0.0.2", NATConfig{Mapping: AddressPortDependent, Filtering: AddressPortDependentFiltering})
	a, b := publicHost(t, n, "203.0.113.1"), publicHost(t, n, "203.0.113.2")
	var want []uint16
	for p := uint16(1); p <= 3; p++ {
		want = append(want, observed(t, listen(t, h, 5000+p), listen(t, a, p)).Port())
	}
	observed(t, listen(t, h, 6000), listen(t, b, 1))
	slices.Sort(want)
	if got := n.Ports(ip("198.51.100.1"), a); !slices.Equal(got, want) {
		t.Fatalf("Ports toward a = %v, want %v", got, want)
	}
	if got := n.Ports(ip("203.0.113.1"), b); got != nil {
		t.Fatalf("Ports of a host with no NAT = %v", got)
	}
}
