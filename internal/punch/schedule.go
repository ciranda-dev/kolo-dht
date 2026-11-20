package punch

import (
	"context"
	"math/rand/v2"
	"net/netip"
	"time"
)

// The strategy constants.
const (
	// Sockets is the birthday holders, the node's own socket included.
	Sockets = 256
	// LowTTL lets a packet open our own NAT mapping and die before the peer's NAT.
	LowTTL = 5
	// MinRandomPort is the lowest port a random probe goes to; the highest is 65535.
	MinRandomPort = 1000
	// RandomTries and RandomEvery make the 35s random window, for random probes and the birthday keep-alive.
	RandomTries = 1750
	RandomEvery = 20 * time.Millisecond
	// KeepAliveDelay is the pause between opening the birthday holders and their keep-alive cycle.
	KeepAliveDelay = 100 * time.Millisecond
	// ConsistentTries and ConsistentEvery are the probes of a pair where neither mapping is random.
	ConsistentTries = 10
	ConsistentEvery = time.Second
)

// RandomPort returns a port from MinRandomPort to 65535.
func RandomPort() uint16 {
	return uint16(MinRandomPort + rand.IntN(65536-MinRandomPort))
}

// Run calls tick(0) after delay, then tick(1), tick(2) and so on every every, tries times in all, until stop is
// closed or ctx is done.
func Run(ctx context.Context, stop <-chan struct{}, delay, every time.Duration, tries int, tick func(i int)) {
	wait := func(d time.Duration) bool {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-t.C:
			return true
		case <-stop:
		case <-ctx.Done():
		}
		return false
	}
	if delay > 0 && !wait(delay) {
		return
	}
	var tk *time.Ticker
	for i := range tries {
		select {
		case <-stop:
			return
		case <-ctx.Done():
			return
		default:
		}
		if i > 0 {
			if tk == nil {
				tk = time.NewTicker(every)
				defer tk.Stop()
			}
			select {
			case <-tk.C:
			case <-stop:
				return
			case <-ctx.Done():
				return
			}
		}
		tick(i)
	}
}

// RandomProbes sends tries probes, one every every, each to the port that port picks (RandomPort outside tests) on ip,
// the peer's verified IP. It sends nothing if ip is not IPv4, IPv4-mapped included.
func RandomProbes(ctx context.Context, stop <-chan struct{}, ip netip.Addr, every time.Duration, tries int, port func() uint16, send func(netip.AddrPort)) {
	if !ip.Is4() {
		return
	}
	Run(ctx, stop, 0, every, tries, func(int) { send(netip.AddrPortFrom(ip, port())) })
}

// Birthday keeps holders sockets open after delay: one send per tick, cycling through them, with lowTTL on the
// first pass (it only renews our mappings) and DefaultTTL after, when it may also reach the peer.
func Birthday(ctx context.Context, stop <-chan struct{}, delay, every time.Duration, tries, holders, lowTTL int, send func(i, ttl int)) {
	Run(ctx, stop, delay, every, tries, func(i int) {
		ttl := DefaultTTL
		if i < holders {
			ttl = lowTTL
		}
		send(i%holders, ttl)
	})
}
