// Package ratelimit counts packets per host, per group and in total, in fixed windows.
package ratelimit

import (
	"net/netip"
	"time"

	"github.com/ciranda-dev/kolo-dht/internal/addrs"
)

// Window is the length of one counting window.
const Window = time.Second

// Limiter allows at most perHost packets per host, perGroup per group and total in all per Window.
// Hosts and groups are as in package addrs. It is not safe for concurrent use.
type Limiter struct {
	perHost, perGroup, total int
	start                    time.Time
	n                        int
	hosts, groups            map[netip.Prefix]int
}

// New returns a Limiter whose first window starts at now.
func New(perHost, perGroup, total int, now time.Time) *Limiter {
	return &Limiter{
		perHost:  perHost,
		perGroup: perGroup,
		total:    total,
		start:    now,
		hosts:    make(map[netip.Prefix]int),
		groups:   make(map[netip.Prefix]int),
	}
}

// Allow reports whether one more packet from ip fits; only allowed packets are counted,
// so the maps never hold more than total entries each.
func (l *Limiter) Allow(ip netip.Addr, now time.Time) bool {
	if d := now.Sub(l.start); d >= Window {
		l.start = l.start.Add(d / Window * Window)
		l.n = 0
		clear(l.hosts)
		clear(l.groups)
	}
	if l.n >= l.total {
		return false
	}
	h, g := addrs.Host(ip), addrs.Group(ip)
	if l.hosts[h] >= l.perHost || l.groups[g] >= l.perGroup {
		return false
	}
	l.n++
	l.hosts[h]++
	l.groups[g]++
	return true
}

func (l *Limiter) entries() int { return len(l.hosts) + len(l.groups) }
