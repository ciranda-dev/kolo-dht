package punch

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/net/ipv4"
)

// DefaultTTL is the TTL a socket goes back to when the punch commits it.
const DefaultTTL = 64

// maxDatagram bounds what a holder reads; anything longer is not a probe.
const maxDatagram = 1200

var (
	// ErrClosed means the node closed while a pool was opening.
	ErrClosed  = errors.New("kolodht: punch pool closed")
	errHolder  = errors.New("kolodht: no such punch socket")
	errNoTTL   = errors.New("kolodht: socket cannot set its TTL")
	errNotIPv4 = errors.New("kolodht: punch peer is not IPv4")
)

// Handler gets each datagram that holder i receives from the peer. b is valid until it returns.
type Handler func(i int, b []byte, from netip.AddrPort)

// Pool is the set of sockets a birthday punch opens toward one peer address, the only address they send to and the
// only one whose datagrams they pass on.
type Pool struct {
	peer netip.AddrPort
	h    Handler

	mu      sync.Mutex
	holders []*holder
	closed  bool
}

type holder struct {
	pc     net.PacketConn
	taking bool
	taken  bool
	done   chan struct{}
}

// Open opens k sockets with listen at TTL ttl, each read in a goroutine from spawn, or none on any failure (ErrClosed
// if spawn refuses); a peer that is not IPv4, IPv4-mapped included, is refused first.
func Open(k int, listen func() (net.PacketConn, error), ttl int, peer netip.AddrPort, spawn func(func()) bool, h Handler) (*Pool, error) {
	if !peer.Addr().Is4() {
		return nil, errNotIPv4
	}
	p := &Pool{peer: peer, h: h}
	for range k {
		pc, err := listen()
		if err != nil {
			p.Close()
			return nil, err
		}
		if err := SetTTL(pc, ttl); err != nil {
			pc.Close()
			p.Close()
			return nil, err
		}
		x := &holder{pc: pc, done: make(chan struct{})}
		p.mu.Lock()
		i := len(p.holders)
		p.holders = append(p.holders, x)
		p.mu.Unlock()
		if !spawn(func() { p.read(i, x) }) {
			close(x.done)
			p.Close()
			return nil, ErrClosed
		}
	}
	return p, nil
}

func (p *Pool) read(i int, x *holder) {
	defer close(x.done)
	buf := make([]byte, maxDatagram+1)
	for {
		k, from, err := x.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		ua, ok := from.(*net.UDPAddr)
		if !ok || k > maxDatagram {
			continue
		}
		ap := ua.AddrPort()
		// The OS may report an IPv4 sender in 16 bytes.
		if netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()) != p.peer {
			continue
		}
		p.h(i, buf[:k], p.peer)
	}
}

func (p *Pool) holder(i int) (*holder, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || i < 0 || i >= len(p.holders) || p.holders[i].taking {
		return nil, errHolder
	}
	return p.holders[i], nil
}

// Len returns the number of sockets the pool opened.
func (p *Pool) Len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.holders)
}

// Send writes b from holder i to the peer.
func (p *Pool) Send(i int, b []byte) error {
	x, err := p.holder(i)
	if err != nil {
		return err
	}
	_, err = x.pc.WriteTo(b, net.UDPAddrFromAddrPort(p.peer))
	return err
}

// LocalAddr returns holder i's local address, or the zero address.
func (p *Pool) LocalAddr(i int) netip.AddrPort {
	p.mu.Lock()
	defer p.mu.Unlock()
	if i < 0 || i >= len(p.holders) {
		return netip.AddrPort{}
	}
	ua, ok := p.holders[i].pc.LocalAddr().(*net.UDPAddr)
	if !ok {
		return netip.AddrPort{}
	}
	ap := ua.AddrPort()
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

// SetTTL sets the TTL of holder i's later packets.
func (p *Pool) SetTTL(i, ttl int) error {
	x, err := p.holder(i)
	if err != nil {
		return err
	}
	return SetTTL(x.pc, ttl)
}

// Take stops holder i's reader, sets its TTL back to DefaultTTL and hands its socket to the caller.
func (p *Pool) Take(i int) (net.PacketConn, error) {
	p.mu.Lock()
	if p.closed || i < 0 || i >= len(p.holders) || p.holders[i].taking {
		p.mu.Unlock()
		return nil, errHolder
	}
	x := p.holders[i]
	x.taking = true
	p.mu.Unlock()
	x.pc.SetReadDeadline(time.Unix(1, 0))
	<-x.done
	err := x.pc.SetReadDeadline(time.Time{})
	if err == nil {
		err = SetTTL(x.pc, DefaultTTL)
	}
	p.mu.Lock()
	x.taken = true
	p.mu.Unlock()
	if err != nil {
		x.pc.Close()
		return nil, err
	}
	return x.pc, nil
}

// Close closes every socket not taken, waits for their readers and returns how many it closed. Later calls return 0.
func (p *Pool) Close() int {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return 0
	}
	p.closed = true
	var mine []*holder
	for _, x := range p.holders {
		if !x.taking {
			mine = append(mine, x)
		}
	}
	p.mu.Unlock()
	for _, x := range mine {
		x.pc.Close()
	}
	for _, x := range mine {
		<-x.done
	}
	return len(mine)
}

// SetTTL sets the IPv4 TTL of pc's later packets, with pc's own SetTTL if it has one (the simulator's).
func SetTTL(pc net.PacketConn, ttl int) error {
	switch c := pc.(type) {
	case interface{ SetTTL(int) error }:
		return c.SetTTL(ttl)
	case *net.UDPConn:
		return ipv4.NewPacketConn(c).SetTTL(ttl)
	}
	return errNoTTL
}
