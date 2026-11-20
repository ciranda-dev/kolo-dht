// Package punch has the budget, the birthday socket pool and the probe schedules of kolo-dht's random-mapping
// punches. They send only to an address the storing node proved by a round trip.
package punch

import (
	"maps"
	"net/netip"
	"slices"
	"sync"
	"time"
)

// Role is the side of a punch that asks for a grant.
type Role int

// The roles: the node that called Connect, and the node that answers a relayed PUNCH.
const (
	Connector Role = iota
	Announcer
)

// Limits bound the random punches of one node.
type Limits struct {
	// Punches caps random punches at once, both roles.
	Punches int
	// PerTarget caps the connector's random punches toward one peer IPv4 address.
	PerTarget int
	// PerRequester caps the announcer's random punches for one requester IPv4 address.
	PerRequester int
	// Sockets caps the sockets all punches hold besides the node's own.
	Sockets int
	// Interval is the least time between the end of one random punch and the start of the next.
	Interval time.Duration
	// Cooldown is the least time from the end of a burst to the next with one of its keys; it doubles for a host
	// key after each burst that made no connection, up to 1<<MaxBackoff times.
	Cooldown time.Duration
	// PerMinute caps the bursts started in any minute, both roles.
	PerMinute int
}

// MaxBackoff caps the doublings of a host key's cooldown.
const MaxBackoff = 4

// kind is what a cooldown key's address is, so the keys of one address in two roles never meet.
type kind uint8

const (
	target       kind = iota // the peer IP a connector probes
	requester                // the requester IP an announcer probes or dials
	requesterNet             // that IP's /24
	storer                   // the server that relayed the PUNCH; its cooldown never grows
)

type key struct {
	kind kind
	addr netip.Addr
}

// cooling is a key's last burst start or end and the bursts since its last connection.
type cooling struct {
	last  time.Time
	fails int
}

// Budget hands out grants within Limits. It is safe for concurrent use.
type Budget struct {
	l Limits

	mu      sync.Mutex
	active  int
	hosts   [2]map[netip.Addr]int
	sockets int
	last    time.Time
	// cool keeps a key for 2*Cooldown<<MaxBackoff after its last burst, so at most that many minutes x PerMinute x 3.
	cool   map[key]*cooling
	starts []time.Time // the burst starts of the last minute
}

// NewBudget returns an empty budget.
func NewBudget(l Limits) *Budget {
	return &Budget{l: l, hosts: [2]map[netip.Addr]int{{}, {}}, cool: map[key]*cooling{}}
}

// Grant is one random punch and the sockets it holds.
type Grant struct {
	b         *Budget
	role      Role
	host      netip.Addr
	keys      []key
	sockets   int
	done      bool
	connected bool
}

// Acquire grants a random punch by role for host with sockets sockets, or nothing: false if host is not IPv4
// (IPv4-mapped included), if any limit is reached or if the interval since the last random punch ended has not passed.
func (b *Budget) Acquire(role Role, host netip.Addr, sockets int, now time.Time) (*Grant, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.acquire(role, host, sockets, now)
}

// Burst is Acquire for a punch that sends a burst of probes, with fewer than PerMinute started in the last minute.
// Its keys, host (and for the announcer host's /24 and a valid storer), must be out of their cooldown.
func (b *Budget) Burst(role Role, host netip.Addr, sockets int, now time.Time, from netip.Addr) (*Grant, bool) {
	keys := []key{{target, host}}
	if role == Announcer {
		keys = []key{{requester, host}, {requesterNet, netip.PrefixFrom(host, 24).Masked().Addr()}}
		if from.IsValid() {
			keys = append(keys, key{storer, from})
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.starts = slices.DeleteFunc(b.starts, func(t time.Time) bool { return now.Sub(t) >= time.Minute })
	maps.DeleteFunc(b.cool, func(k key, c *cooling) bool { return now.Sub(c.last) >= 2*b.wait(k, MaxBackoff) })
	if len(b.starts) >= b.l.PerMinute || slices.ContainsFunc(keys, func(k key) bool { return b.cooling(k, now) }) {
		return nil, false
	}
	g, ok := b.acquire(role, host, sockets, now)
	if !ok {
		return nil, false
	}
	g.keys = keys
	b.starts = append(b.starts, now)
	for _, k := range keys {
		if c := b.cool[k]; c != nil {
			c.last = now
		} else {
			b.cool[k] = &cooling{last: now}
		}
	}
	return g, true
}

// Refused reports whether Burst would refuse a connector's burst toward host at now.
func (b *Budget) Refused(host netip.Addr, now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for _, t := range b.starts {
		if now.Sub(t) < time.Minute {
			n++
		}
	}
	return n >= b.l.PerMinute || b.cooling(key{target, host}, now) || !host.Is4() || b.active >= b.l.Punches ||
		b.hosts[Connector][host] >= b.l.PerTarget || (!b.last.IsZero() && now.Sub(b.last) < b.l.Interval)
}

// wait is k's cooldown after fails bursts without a connection.
func (b *Budget) wait(k key, fails int) time.Duration {
	if k.kind == storer {
		return b.l.Cooldown
	}
	return b.l.Cooldown << min(fails, MaxBackoff)
}

func (b *Budget) cooling(k key, now time.Time) bool {
	c := b.cool[k]
	return c != nil && now.Sub(c.last) < b.wait(k, c.fails)
}

func (b *Budget) acquire(role Role, host netip.Addr, sockets int, now time.Time) (*Grant, bool) {
	per := b.l.PerTarget
	if role == Announcer {
		per = b.l.PerRequester
	}
	switch {
	case !host.Is4() || sockets < 0 || b.active >= b.l.Punches || b.hosts[role][host] >= per:
		return nil, false
	case b.sockets+sockets > b.l.Sockets:
		return nil, false
	case !b.last.IsZero() && now.Sub(b.last) < b.l.Interval:
		return nil, false
	}
	b.active++
	b.hosts[role][host]++
	b.sockets += sockets
	return &Grant{b: b, role: role, host: host, sockets: sockets}, true
}

// Done ends the random punch when its probes end: its slot comes back and the interval and a burst's cooldowns
// start at now, or not at all for a zero now. Its sockets stay counted until ReleaseSockets; later calls do nothing.
func (g *Grant) Done(now time.Time) {
	b := g.b
	b.mu.Lock()
	defer b.mu.Unlock()
	if g.done {
		return
	}
	g.done = true
	b.active--
	if b.hosts[g.role][g.host]--; b.hosts[g.role][g.host] <= 0 {
		delete(b.hosts[g.role], g.host)
	}
	if now.After(b.last) {
		b.last = now
	}
	if now.IsZero() {
		return
	}
	for _, k := range g.keys {
		c := b.cool[k]
		if c == nil {
			c = &cooling{}
			b.cool[k] = c
		}
		c.last = now
		if g.connected {
			c.fails = 0
		} else {
			c.fails++
		}
	}
}

// Connected records that the punch made a connection, before or after Done, so its keys' cooldowns stop growing.
func (g *Grant) Connected() {
	b := g.b
	b.mu.Lock()
	defer b.mu.Unlock()
	g.connected = true
	if !g.done {
		return
	}
	for _, k := range g.keys {
		if c := b.cool[k]; c != nil {
			c.fails = 0
		}
	}
}

// ReleaseSockets gives back k of the grant's sockets, at most as many as it still holds.
func (g *Grant) ReleaseSockets(k int) {
	b := g.b
	b.mu.Lock()
	defer b.mu.Unlock()
	k = max(0, min(k, g.sockets))
	g.sockets -= k
	b.sockets -= k
}

// Active returns the random punches in progress.
func (b *Budget) Active() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.active
}

// Sockets returns the sockets the grants hold.
func (b *Budget) Sockets() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sockets
}
