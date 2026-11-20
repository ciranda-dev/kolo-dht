// Package token makes and checks round-trip tokens that prove a sender received a recent packet at its address.
package token

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"net/netip"
	"time"
)

// Size is the length of a token in bytes.
const Size = sha256.Size

// Rotation is how often the secret changes; a token is accepted for Rotation to twice Rotation.
// It covers the longest measured gap between a reply and the use of its token: 31s, a refresh after a lost reply.
const Rotation = 40 * time.Second

// Secret holds the current and previous secrets. It is not safe for concurrent use.
type Secret struct {
	cur, prev [32]byte
	rotated   time.Time
}

// New returns a Secret with fresh random secrets.
func New(now time.Time) *Secret {
	s := &Secret{rotated: now}
	rand.Read(s.cur[:])
	rand.Read(s.prev[:])
	return s
}

// rotate moves to the epoch of now; epochs start at fixed multiples of Rotation, so a token lives at most two epochs.
func (s *Secret) rotate(now time.Time) {
	n := now.Sub(s.rotated) / Rotation
	switch {
	case n <= 0:
		return
	case n == 1:
		s.prev = s.cur
		rand.Read(s.cur[:])
	default:
		rand.Read(s.prev[:])
		rand.Read(s.cur[:])
	}
	s.rotated = s.rotated.Add(n * Rotation)
}

func mac(secret [32]byte, ap netip.AddrPort) [Size]byte {
	var msg [6]byte
	ip := ap.Addr().As4()
	copy(msg[:4], ip[:])
	binary.BigEndian.PutUint16(msg[4:], ap.Port())
	h := hmac.New(sha256.New, secret[:])
	h.Write(msg[:])
	var out [Size]byte
	h.Sum(out[:0])
	return out
}

// Make returns the token for ap, bound to its IP and port; for an IPv6 ap it is all zeros, which never passes Check.
func (s *Secret) Make(ap netip.AddrPort, now time.Time) [Size]byte {
	if !ap.Addr().Is4() {
		return [Size]byte{}
	}
	s.rotate(now)
	return mac(s.cur, ap)
}

// Check reports whether tok was made for ap with the current or the previous secret; an IPv6 ap, IPv4-mapped
// included, never passes (kolo-dht is IPv4 only).
func (s *Secret) Check(ap netip.AddrPort, tok [Size]byte, now time.Time) bool {
	if !ap.Addr().Is4() {
		return false
	}
	s.rotate(now)
	cur, prev := mac(s.cur, ap), mac(s.prev, ap)
	return hmac.Equal(cur[:], tok[:]) || hmac.Equal(prev[:], tok[:])
}
