// Package netsim is an in-process UDP network with NAT boxes that follow the RFC 4787 mapping and filtering
// behaviors. Each socket is a net.PacketConn with *net.UDPAddr addresses. It is for tests only; nothing leaves the process.
package netsim

import (
	"errors"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"time"
)

// Mapping is a NAT mapping behavior (RFC 4787 section 4.1).
type Mapping int

// The mapping behaviors.
const (
	EndpointIndependent Mapping = iota
	AddressDependent
	AddressPortDependent
	// Conntrack maps each flow on its own, keeping the internal port unless another internal endpoint already uses it
	// toward the same destination, as Linux netfilter does; only the exact flow comes back in.
	Conntrack
)

// String returns the name of the mapping behavior.
func (m Mapping) String() string {
	return [...]string{"endpoint-independent", "address-dependent", "address-and-port-dependent", "conntrack"}[m]
}

// Filtering is a NAT filtering behavior (RFC 4787 section 5).
type Filtering int

// The filtering behaviors.
const (
	EndpointIndependentFiltering Filtering = iota
	AddressDependentFiltering
	AddressPortDependentFiltering
)

// String returns the name of the filtering behavior.
func (f Filtering) String() string {
	return [...]string{"endpoint-independent", "address-dependent", "address-and-port-dependent"}[f]
}

// NATConfig describes a NAT box. The zero value is a full cone NAT (EIM, EIF) whose mappings never expire.
type NATConfig struct {
	Mapping   Mapping
	Filtering Filtering
	// Timeout ends a mapping, and each destination's filter entry, this long after its last outbound packet; 0 never.
	// Inbound packets never refresh (RFC 4787 REQ-6).
	Timeout time.Duration
	// Hairpin forwards packets to the NAT's own external address back inside, from the sender's mapping (REQ-9).
	Hairpin bool
	// PreservePort keeps the internal port as the external one when it is free.
	PreservePort bool
	// Blocked drops all UDP in both directions.
	Blocked bool
}

// Config sets up a Network.
type Config struct {
	// Latency delays every packet by this much; 0 delivers before WriteTo returns.
	Latency time.Duration
	// Loss is the probability, from 0 to 1, that a packet is dropped.
	Loss float64
	// Seed makes port assignment and loss repeatable.
	Seed uint64
	// Now is the clock of NAT timers; nil means time.Now. Read deadlines always use real time.
	Now func() time.Time
	// QueueLen is the number of packets a socket buffers; 0 means 256. More are dropped.
	QueueLen int
	// Hops is the number of routers between any two NATs or public hosts, besides the NATs themselves; 0 means 8.
	Hops int
	// Tap, if set, sees every packet sent, before loss and latency.
	Tap func(Packet)
}

// Packet describes one sent packet for Config.Tap: the sender's own address, the destination, the payload size, the
// TTL it left with, and whether it reached a socket.
type Packet struct {
	From, To  netip.AddrPort
	Size, TTL int
	Delivered bool
}

// DefaultTTL is the TTL of a new socket's packets.
const DefaultTTL = 64

var (
	errAddrInUse = errors.New("kolodht: netsim: address in use")
	errNotUDP    = errors.New("kolodht: netsim: not a UDP address")
	errNotIPv4   = errors.New("kolodht: netsim: not an IPv4 address")
	errBadTTL    = errors.New("kolodht: netsim: TTL out of range")
)

// Network is a set of public hosts and NATs. It is safe for concurrent use.
type Network struct {
	cfg Config

	mu     sync.Mutex
	rng    *rand.Rand
	public map[netip.Addr]*Host
	nats   map[netip.Addr]*NAT
}

// New returns an empty network.
func New(cfg Config) *Network {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.QueueLen == 0 {
		cfg.QueueLen = 256
	}
	if cfg.Hops == 0 {
		cfg.Hops = 8
	}
	return &Network{
		cfg:    cfg,
		rng:    rand.New(rand.NewPCG(cfg.Seed, cfg.Seed^0x9e3779b97f4a7c15)),
		public: make(map[netip.Addr]*Host),
		nats:   make(map[netip.Addr]*NAT),
	}
}

func (n *Network) taken(ip netip.Addr) bool {
	return n.public[ip] != nil || n.nats[ip] != nil
}

// AddHost adds a host with a public IPv4 address.
func (n *Network) AddHost(ip netip.Addr) (*Host, error) {
	if !ip.Is4() {
		return nil, errNotIPv4
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.taken(ip) {
		return nil, errAddrInUse
	}
	h := newHost(n, nil, ip)
	n.public[ip] = h
	return h, nil
}

// AddNAT adds a NAT box with the public IPv4 address ip.
func (n *Network) AddNAT(ip netip.Addr, cfg NATConfig) (*NAT, error) {
	if !ip.Is4() {
		return nil, errNotIPv4
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.taken(ip) {
		return nil, errAddrInUse
	}
	nat := &NAT{
		net:      n,
		cfg:      cfg,
		public:   ip,
		hosts:    make(map[netip.Addr]*Host),
		mappings: make(map[mapKey]*mapping),
		byPort:   make(map[uint16]*mapping),
		flows:    make(map[flow]*mapping),
	}
	n.nats[ip] = nat
	return nat, nil
}

// NAT is a NAT box with one external address (paired pooling, RFC 4787 REQ-2) and a private network behind it.
type NAT struct {
	net      *Network
	cfg      NATConfig
	public   netip.Addr
	hosts    map[netip.Addr]*Host
	mappings map[mapKey]*mapping
	byPort   map[uint16]*mapping
	flows    map[flow]*mapping // Conntrack only, by external port and remote
}

type mapKey struct {
	src netip.AddrPort
	dst netip.AddrPort // zero for EIM, port 0 for ADM
}

type flow struct {
	ext    uint16
	remote netip.AddrPort
}

type mapping struct {
	key   mapKey
	ext   uint16
	last  time.Time
	perms map[netip.AddrPort]time.Time // destinations sent to (port 0 under ADF), for filtering
}

// AddHost adds a host with a private IPv4 address behind the NAT.
func (nat *NAT) AddHost(ip netip.Addr) (*Host, error) {
	if !ip.Is4() {
		return nil, errNotIPv4
	}
	nat.net.mu.Lock()
	defer nat.net.mu.Unlock()
	if nat.hosts[ip] != nil {
		return nil, errAddrInUse
	}
	h := newHost(nat.net, nat, ip)
	nat.hosts[ip] = h
	return h, nil
}

// Addr returns the NAT's external address.
func (nat *NAT) Addr() netip.Addr { return nat.public }

func (nat *NAT) expired(t, now time.Time) bool {
	return nat.cfg.Timeout > 0 && now.Sub(t) >= nat.cfg.Timeout
}

func (nat *NAT) drop(m *mapping) {
	delete(nat.mappings, m.key)
	if nat.cfg.Mapping == Conntrack {
		delete(nat.flows, flow{m.ext, m.key.dst})
		return
	}
	delete(nat.byPort, m.ext)
}

func (nat *NAT) permKey(dst netip.AddrPort) netip.AddrPort {
	if nat.cfg.Filtering == AddressDependentFiltering {
		return netip.AddrPortFrom(dst.Addr(), 0)
	}
	return dst
}

// outbound finds or creates the mapping for a packet from src to dst, refreshes it, and returns the external source.
func (nat *NAT) outbound(src, dst netip.AddrPort, now time.Time) netip.AddrPort {
	k := mapKey{src: src}
	switch nat.cfg.Mapping {
	case AddressDependent:
		k.dst = netip.AddrPortFrom(dst.Addr(), 0)
	case AddressPortDependent, Conntrack:
		k.dst = dst
	}
	m := nat.mappings[k]
	if m != nil && nat.expired(m.last, now) {
		nat.drop(m)
		m = nil
	}
	if m == nil {
		m = &mapping{key: k, perms: make(map[netip.AddrPort]time.Time)}
		if nat.cfg.Mapping == Conntrack {
			m.ext = nat.flowPort(src.Port(), dst)
			nat.flows[flow{m.ext, dst}] = m
		} else {
			m.ext = nat.port(src.Port())
			nat.byPort[m.ext] = m
		}
		nat.mappings[k] = m
	}
	m.last = now
	m.perms[nat.permKey(dst)] = now
	return netip.AddrPortFrom(nat.public, m.ext)
}

func (nat *NAT) port(internal uint16) uint16 {
	if nat.cfg.PreservePort && nat.byPort[internal] == nil {
		return internal
	}
	for {
		p := uint16(1024 + nat.net.rng.IntN(65536-1024))
		if nat.byPort[p] == nil {
			return p
		}
	}
}

// flowPort keeps internal unless a flow from another endpoint already uses it toward dst, then picks a random free port.
func (nat *NAT) flowPort(internal uint16, dst netip.AddrPort) uint16 {
	if nat.flows[flow{internal, dst}] == nil {
		return internal
	}
	for {
		p := uint16(1024 + nat.net.rng.IntN(65536-1024))
		if nat.flows[flow{p, dst}] == nil {
			return p
		}
	}
}

// inbound returns the socket a packet from src to the external port reaches, if the mapping and filter allow it.
func (nat *NAT) inbound(src netip.AddrPort, port uint16, now time.Time) *Conn {
	m := nat.byPort[port]
	if nat.cfg.Mapping == Conntrack {
		m = nat.flows[flow{port, src}]
	}
	if m == nil {
		return nil
	}
	if nat.expired(m.last, now) {
		nat.drop(m)
		return nil
	}
	if nat.cfg.Filtering != EndpointIndependentFiltering {
		t, ok := m.perms[nat.permKey(src)]
		if !ok || nat.expired(t, now) {
			return nil
		}
	}
	h := nat.hosts[m.key.src.Addr()]
	if h == nil {
		return nil
	}
	return h.conns[m.key.src.Port()]
}

// Ports returns, sorted, the external ports of the live mappings of the NAT at ip that let packets from h's public
// address in, for tests that aim a peer's random probes.
func (n *Network) Ports(ip netip.Addr, h *Host) []uint16 {
	n.mu.Lock()
	defer n.mu.Unlock()
	nat := n.nats[ip]
	if nat == nil {
		return nil
	}
	from := h.ip
	if h.nat != nil {
		from = h.nat.public
	}
	now := n.cfg.Now()
	var out []uint16
	for _, m := range nat.mappings {
		if nat.expired(m.last, now) {
			continue
		}
		for d, t := range m.perms {
			if d.Addr() == from && !nat.expired(t, now) {
				out = append(out, m.ext)
				break
			}
		}
	}
	slices.Sort(out)
	return out
}

// Host is a machine with one address, public or behind a NAT.
type Host struct {
	net   *Network
	nat   *NAT
	ip    netip.Addr
	conns map[uint16]*Conn
	next  uint16
}

func newHost(n *Network, nat *NAT, ip netip.Addr) *Host {
	return &Host{net: n, nat: nat, ip: ip, conns: make(map[uint16]*Conn), next: 49152}
}

// Addr returns the host's own address (private if behind a NAT).
func (h *Host) Addr() netip.Addr { return h.ip }

// ListenUDP opens a socket on port, or on a free port from 49152 if port is 0.
func (h *Host) ListenUDP(port uint16) (*Conn, error) {
	h.net.mu.Lock()
	defer h.net.mu.Unlock()
	if port == 0 {
		for h.conns[h.next] != nil || h.next == 0 {
			h.next++
		}
		port = h.next
		h.next++
	}
	if h.conns[port] != nil {
		return nil, errAddrInUse
	}
	c := &Conn{
		host:    h,
		addr:    netip.AddrPortFrom(h.ip, port),
		queue:   make(chan packet, h.net.cfg.QueueLen),
		closed:  make(chan struct{}),
		changed: make(chan struct{}),
		ttl:     DefaultTTL,
	}
	h.conns[port] = c
	return c, nil
}

// route returns the socket a packet from c to dst with ttl reaches and the source address it shows there, or nil.
// Every router, NATs included, takes one from the TTL and drops the packet when nothing is left.
func (n *Network) route(c *Conn, dst netip.AddrPort, ttl int, now time.Time) (*Conn, netip.AddrPort) {
	src := c.addr
	if nat := c.host.nat; nat != nil {
		if nat.cfg.Blocked {
			return nil, netip.AddrPort{}
		}
		if h := nat.hosts[dst.Addr()]; h != nil {
			return h.conns[dst.Port()], src
		}
		if ttl--; ttl <= 0 {
			return nil, netip.AddrPort{}
		}
		src = nat.outbound(src, dst, now)
		if dst.Addr() == nat.public {
			if !nat.cfg.Hairpin {
				return nil, netip.AddrPort{}
			}
			return nat.inbound(src, dst.Port(), now), src
		}
	}
	if ttl -= n.cfg.Hops; ttl <= 0 {
		return nil, netip.AddrPort{}
	}
	if h := n.public[dst.Addr()]; h != nil {
		return h.conns[dst.Port()], src
	}
	if nat := n.nats[dst.Addr()]; nat != nil && !nat.cfg.Blocked && ttl > 1 {
		return nat.inbound(src, dst.Port(), now), src
	}
	return nil, netip.AddrPort{}
}

// Inject delivers b to to as if from had sent it from the public network, for tests of spoofed sources.
func (n *Network) Inject(from, to netip.AddrPort, b []byte) {
	n.mu.Lock()
	var c *Conn
	if h := n.public[to.Addr()]; h != nil {
		c = h.conns[to.Port()]
	} else if nat := n.nats[to.Addr()]; nat != nil && !nat.cfg.Blocked {
		c = nat.inbound(from, to.Port(), n.cfg.Now())
	}
	n.mu.Unlock()
	if c != nil {
		c.push(packet{b: append([]byte(nil), b...), from: from})
	}
}

type packet struct {
	b    []byte
	from netip.AddrPort
}

// Conn is a UDP socket on the simulated network.
type Conn struct {
	host *Host
	addr netip.AddrPort

	queue     chan packet
	closed    chan struct{}
	closeOnce sync.Once

	mu       sync.Mutex
	deadline time.Time
	changed  chan struct{} // closed and replaced when the deadline changes
	ttl      int
}

// SetTTL sets the TTL of the socket's later packets, from 1 to 255; a new socket uses DefaultTTL.
func (c *Conn) SetTTL(ttl int) error {
	if ttl < 1 || ttl > 255 {
		return errBadTTL
	}
	c.mu.Lock()
	c.ttl = ttl
	c.mu.Unlock()
	return nil
}

// Host returns the host the socket is on.
func (c *Conn) Host() *Host { return c.host }

// Addr returns the socket's own address.
func (c *Conn) Addr() netip.AddrPort { return c.addr }

// LocalAddr returns the socket's own address as a *net.UDPAddr.
func (c *Conn) LocalAddr() net.Addr { return net.UDPAddrFromAddrPort(c.addr) }

func (c *Conn) push(p packet) {
	select {
	case <-c.closed:
	case c.queue <- p:
	default:
	}
}

// WriteTo sends b to addr, which must be a *net.UDPAddr with an IPv4 address. Packets that reach no socket are dropped
// silently.
func (c *Conn) WriteTo(b []byte, addr net.Addr) (int, error) {
	ua, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, &net.OpError{Op: "write", Net: "udp", Err: errNotUDP}
	}
	select {
	case <-c.closed:
		return 0, &net.OpError{Op: "write", Net: "udp", Err: net.ErrClosed}
	default:
	}
	dst := ua.AddrPort()
	dst = netip.AddrPortFrom(dst.Addr().Unmap(), dst.Port()) // net.IP has no separate IPv4-mapped form
	if !dst.Addr().Is4() {
		return 0, &net.OpError{Op: "write", Net: "udp", Err: errNotIPv4}
	}
	c.mu.Lock()
	ttl := c.ttl
	c.mu.Unlock()
	n := c.host.net
	n.mu.Lock()
	to, from := n.route(c, dst, ttl, n.cfg.Now())
	lost := n.cfg.Loss > 0 && n.rng.Float64() < n.cfg.Loss
	n.mu.Unlock()
	if n.cfg.Tap != nil {
		n.cfg.Tap(Packet{From: c.addr, To: dst, Size: len(b), TTL: ttl, Delivered: to != nil && !lost})
	}
	if to == nil || lost {
		return len(b), nil
	}
	p := packet{b: append([]byte(nil), b...), from: from}
	if n.cfg.Latency > 0 {
		time.AfterFunc(n.cfg.Latency, func() { to.push(p) })
	} else {
		to.push(p)
	}
	return len(b), nil
}

// ReadFrom waits for the next packet; a short b truncates it, as UDP does.
func (c *Conn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		c.mu.Lock()
		deadline, changed := c.deadline, c.changed
		c.mu.Unlock()
		var timer *time.Timer
		var timeout <-chan time.Time
		if !deadline.IsZero() {
			d := time.Until(deadline)
			if d <= 0 {
				return 0, nil, &net.OpError{Op: "read", Net: "udp", Err: os.ErrDeadlineExceeded}
			}
			timer = time.NewTimer(d)
			timeout = timer.C
		}
		var p packet
		var ok, done bool
		select {
		case p = <-c.queue:
			ok = true
		case <-c.closed:
			done = true
		case <-timeout:
		case <-changed:
		}
		if timer != nil {
			timer.Stop()
		}
		switch {
		case ok:
			return copy(b, p.b), net.UDPAddrFromAddrPort(p.from), nil
		case done:
			return 0, nil, &net.OpError{Op: "read", Net: "udp", Err: net.ErrClosed}
		}
	}
}

// SetReadDeadline sets the deadline for ReadFrom; it wakes a blocked reader.
func (c *Conn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadline = t
	close(c.changed)
	c.changed = make(chan struct{})
	return nil
}

// SetDeadline sets the read deadline; writes never block.
func (c *Conn) SetDeadline(t time.Time) error { return c.SetReadDeadline(t) }

// SetWriteDeadline does nothing: writes never block.
func (c *Conn) SetWriteDeadline(time.Time) error { return nil }

// SetReadBuffer does nothing; it exists so quic-go does not warn about buffer sizes.
func (c *Conn) SetReadBuffer(int) error { return nil }

// SetWriteBuffer does nothing; it exists so quic-go does not warn about buffer sizes.
func (c *Conn) SetWriteBuffer(int) error { return nil }

// Close closes the socket and frees its port.
func (c *Conn) Close() error {
	err := error(&net.OpError{Op: "close", Net: "udp", Err: net.ErrClosed})
	c.closeOnce.Do(func() {
		err = nil
		close(c.closed)
		n := c.host.net
		n.mu.Lock()
		delete(c.host.conns, c.addr.Port())
		n.mu.Unlock()
	})
	return err
}
