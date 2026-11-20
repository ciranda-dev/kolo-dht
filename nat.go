package kolodht

import (
	"net/netip"
	"slices"
	"time"

	"github.com/ciranda-dev/kolo-dht/internal/addrs"
	"github.com/ciranda-dev/kolo-dht/internal/wire"
)

const (
	// maxSamples is the window; minSamples the fewest live samples that classify.
	maxSamples = 16
	minSamples = 3
)

type sample struct {
	key      netip.AddrPort
	observed netip.AddrPort
	at       time.Time
}

// natState keeps the addresses servers saw for us, one sample per server /24 (per server address on loopback), for
// at most age, so one network counts once and old samples leave.
type natState struct {
	samples []sample
	age     time.Duration
	settled netip.AddrPort // the last majority address
}

func newNAT(age time.Duration) *natState { return &natState{age: age} }

// sampleKey is the server's /24, so one network counts once; a loopback server runs on this host, behind no NAT, and
// counts by its own address.
func sampleKey(server netip.AddrPort) netip.AddrPort {
	if server.Addr().IsLoopback() {
		return server
	}
	return netip.AddrPortFrom(addrs.Group(server.Addr()).Addr(), 0)
}

func (s *natState) expire(now time.Time) {
	s.samples = slices.DeleteFunc(s.samples, func(x sample) bool { return now.Sub(x.at) >= s.age })
}

// add records that server saw us at observed. When another address than the last majority gains a majority, the
// network changed: the samples that disagree with it are dropped.
func (s *natState) add(server, observed netip.AddrPort, now time.Time) {
	s.expire(now)
	k := sampleKey(server)
	s.samples = slices.DeleteFunc(s.samples, func(x sample) bool { return x.key == k })
	s.samples = append(s.samples, sample{k, observed, now})
	if len(s.samples) > maxSamples {
		s.samples = slices.Delete(s.samples, 0, 1)
	}
	ap, ok := s.majority()
	if !ok || ap == s.settled {
		return
	}
	if s.settled.IsValid() {
		s.samples = slices.DeleteFunc(s.samples, func(x sample) bool { return x.observed != ap })
	}
	s.settled = ap
}

func (s *natState) observed(ap netip.AddrPort) bool {
	return slices.ContainsFunc(s.samples, func(x sample) bool { return x.observed == ap })
}

// majority returns the address that more than half of the samples report, if there are at least minSamples.
func (s *natState) majority() (netip.AddrPort, bool) {
	if len(s.samples) < minSamples {
		return netip.AddrPort{}, false
	}
	count := map[netip.AddrPort]int{}
	for _, x := range s.samples {
		if count[x.observed]++; 2*count[x.observed] > len(s.samples) {
			return x.observed, true
		}
	}
	return netip.AddrPort{}, false
}

// class is unknown below minSamples live samples, consistent when more than half of them report one address, and
// random otherwise.
func (s *natState) class(now time.Time) wire.Class {
	s.expire(now)
	if len(s.samples) < minSamples {
		return wire.ClassUnknown
	}
	if _, ok := s.majority(); ok {
		return wire.ClassConsistent
	}
	return wire.ClassRandom
}

func (s *natState) ipCount(ip netip.Addr) int {
	n := 0
	for _, x := range s.samples {
		if x.observed.Addr() == ip {
			n++
		}
	}
	return n
}

// publicIP returns the IP that most samples report, if at least two do.
func (s *natState) publicIP() (netip.Addr, bool) {
	var best netip.Addr
	for _, x := range s.samples {
		if ip := x.observed.Addr(); s.ipCount(ip) >= s.ipCount(best) {
			best = ip
		}
	}
	return best, s.ipCount(best) >= 2
}

// trusted reports whether we may sign obs: the majority address, or with no majority one whose IP more than half of
// the samples report. Below minSamples the samples cannot outvote a liar, so it must be a reported address, if any.
func (s *natState) trusted(obs netip.AddrPort, now time.Time) bool {
	s.expire(now)
	switch {
	case len(s.samples) == 0:
		return true
	case len(s.samples) < minSamples:
		return s.observed(obs)
	}
	if ap, ok := s.majority(); ok {
		return obs == ap
	}
	return 2*s.ipCount(obs.Addr()) > len(s.samples)
}
