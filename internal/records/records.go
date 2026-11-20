// Package records signs and verifies topic announcements and stores them with limits.
package records

import (
	"container/list"
	"errors"
	"math/rand/v2"
	"net/netip"
	"time"

	kolocodec "github.com/ciranda-dev/kolo-codec"
	"github.com/ciranda-dev/kolo-dht/internal/addrs"
	"github.com/ciranda-dev/kolo-dht/internal/wire"
	koloid "github.com/ciranda-dev/kolo-id"
)

// Context is the Ed25519ctx context of an announcement signature.
const Context = "kolo-dht/announce/v1"

const version = 0

var errInvalid = errors.New("kolodht: invalid record")

// Record is an announcement: Key is at Addr for Topic, signed by Key. Share is the announcer's X25519 key and Secret
// the punch secret a server derived from it; neither is signed.
type Record struct {
	Topic     [32]byte
	Key       [wire.KeySize]byte
	Addr      netip.AddrPort
	Sig       [wire.SigSize]byte
	Share     [wire.ShareSize]byte
	Secret    [32]byte
	Refreshed time.Time
}

// Signable returns the signed bytes: uvarint(0) ‖ topic ‖ key ‖ addr (as wire.PutAddr), or wire.ErrInvalid for an
// address PutAddr refuses.
func Signable(topic [32]byte, key [wire.KeySize]byte, addr netip.AddrPort) ([]byte, error) {
	var e kolocodec.Encoder
	e.PutUvarint(version)
	e.PutFixed(topic[:])
	e.PutFixed(key[:])
	if err := wire.PutAddr(&e, addr); err != nil {
		return nil, err
	}
	return e.Bytes(), nil
}

// Sign returns the record of id at addr for topic.
func Sign(id *koloid.Identity, topic [32]byte, addr netip.AddrPort) (Record, error) {
	pub := id.PublicKey()
	if pub == nil || !addrs.Usable(addr) {
		return Record{}, errInvalid
	}
	r := Record{Topic: topic, Addr: addr}
	copy(r.Key[:], pub)
	msg, err := Signable(topic, r.Key, addr)
	if err != nil {
		return Record{}, errInvalid
	}
	sig, err := id.Sign(Context, msg)
	if err != nil {
		return Record{}, err
	}
	copy(r.Sig[:], sig)
	return r, nil
}

// Verify reports whether r is at a usable IPv4 address and signed by its key; kolo-id rejects small-order keys.
func Verify(r Record) bool {
	msg, err := Signable(r.Topic, r.Key, r.Addr)
	return err == nil && addrs.Usable(r.Addr) && koloid.Verify(r.Key[:], Context, msg, r.Sig[:])
}

// Limits bounds a Store.
type Limits struct {
	// Records caps all records, PerTopic those of one topic, PerHost those of one announcing host (all topics), and
	// PerGroup those of one topic from one IPv4 /24, so a few hosts in one network cannot fill a topic.
	Records, PerTopic, PerHost, PerGroup int
	// TTL is how long a record lives after its last refresh.
	TTL time.Duration
}

// Result is the outcome of Put.
type Result int

// The results.
const (
	// Stored: a new record was stored.
	Stored Result = iota
	// Refreshed: the record of this topic and key was refreshed, possibly with a new address.
	Refreshed
	// BadSignature: the record does not verify; nothing changed.
	BadSignature
	// Full: a limit is reached; nothing changed. Live records are never evicted.
	Full
	// Invalid: the address is not usable.
	Invalid
)

// group is a topic and the first 3 bytes of an IPv4 address (its /24). Map keys here have no pointers, which keeps
// them small.
type group struct {
	topic [32]byte
	net   [3]byte
}

// Store holds verified records within its Limits. Calls must pass a non-decreasing now. It is not safe for concurrent use.
type Store struct {
	lim    Limits
	topics map[[32]byte]map[[wire.KeySize]byte]*list.Element
	hosts  map[[4]byte]int
	groups map[group]int
	order  *list.List // of *Record, least recently refreshed first
}

// NewStore returns an empty Store.
func NewStore(l Limits) *Store {
	return &Store{
		lim:    l,
		topics: make(map[[32]byte]map[[wire.KeySize]byte]*list.Element),
		hosts:  make(map[[4]byte]int),
		groups: make(map[group]int),
		order:  list.New(),
	}
}

func hostOf(a netip.AddrPort) [4]byte { return a.Addr().As4() }

func groupOf(topic [32]byte, a netip.AddrPort) group {
	ip := a.Addr().As4()
	return group{topic, [3]byte(ip[:3])}
}

func (s *Store) expire(now time.Time) {
	for el := s.order.Front(); el != nil; el = s.order.Front() {
		r := el.Value.(*Record)
		if now.Sub(r.Refreshed) < s.lim.TTL {
			return
		}
		s.remove(el)
	}
}

func (s *Store) remove(el *list.Element) {
	r := s.order.Remove(el).(*Record)
	m := s.topics[r.Topic]
	delete(m, r.Key)
	if len(m) == 0 {
		delete(s.topics, r.Topic)
	}
	s.unhost(r.Topic, r.Addr)
}

func (s *Store) host(topic [32]byte, a netip.AddrPort) {
	s.hosts[hostOf(a)]++
	s.groups[groupOf(topic, a)]++
}

func (s *Store) unhost(topic [32]byte, a netip.AddrPort) {
	h, g := hostOf(a), groupOf(topic, a)
	if s.hosts[h]--; s.hosts[h] <= 0 {
		delete(s.hosts, h)
	}
	if s.groups[g]--; s.groups[g] <= 0 {
		delete(s.groups, g)
	}
}

// Put stores or refreshes r at now. A record with the stored address and signature is refreshed without checking its
// signature again; its Share and Secret are r's.
func (s *Store) Put(r Record, now time.Time) Result {
	return s.put(r, now, false)
}

// PutVerified is Put for a record whose signature the caller already checked with Verify, or that has the signature
// of a stored record, so the caller can verify without holding the lock that guards the Store.
func (s *Store) PutVerified(r Record, now time.Time) Result {
	return s.put(r, now, true)
}

func (s *Store) put(r Record, now time.Time, verified bool) Result {
	s.expire(now)
	if !addrs.Usable(r.Addr) {
		return Invalid
	}
	r.Refreshed = now
	if el, ok := s.topics[r.Topic][r.Key]; ok {
		old := el.Value.(*Record)
		if old.Addr == r.Addr && old.Sig == r.Sig {
			old.Share, old.Secret, old.Refreshed = r.Share, r.Secret, now
			s.order.MoveToBack(el)
			return Refreshed
		}
		if h := hostOf(r.Addr); h != hostOf(old.Addr) && s.hosts[h] >= s.lim.PerHost {
			return Full
		}
		if g := groupOf(r.Topic, r.Addr); g != groupOf(old.Topic, old.Addr) && s.groups[g] >= s.lim.PerGroup {
			return Full
		}
		if !verified && !Verify(r) {
			return BadSignature
		}
		s.unhost(old.Topic, old.Addr)
		s.host(r.Topic, r.Addr)
		*old = r
		s.order.MoveToBack(el)
		return Refreshed
	}
	if s.order.Len() >= s.lim.Records || len(s.topics[r.Topic]) >= s.lim.PerTopic || s.hosts[hostOf(r.Addr)] >= s.lim.PerHost ||
		s.groups[groupOf(r.Topic, r.Addr)] >= s.lim.PerGroup {
		return Full
	}
	if !verified && !Verify(r) {
		return BadSignature
	}
	m := s.topics[r.Topic]
	if m == nil {
		m = make(map[[wire.KeySize]byte]*list.Element)
		s.topics[r.Topic] = m
	}
	m[r.Key] = s.order.PushBack(&r)
	s.host(r.Topic, r.Addr)
	return Stored
}

// Find returns the live record of key for topic.
func (s *Store) Find(topic [32]byte, k [wire.KeySize]byte, now time.Time) (Record, bool) {
	s.expire(now)
	el, ok := s.topics[topic][k]
	if !ok {
		return Record{}, false
	}
	return *el.Value.(*Record), true
}

// Get returns up to n live records of topic, chosen at random.
func (s *Store) Get(topic [32]byte, n int, now time.Time) []Record {
	s.expire(now)
	m := s.topics[topic]
	out := make([]Record, 0, min(n, len(m)))
	i := 0
	for _, el := range m {
		// Reservoir sampling: each record ends up in out with probability n/len(m), and only out is copied.
		if len(out) < n {
			out = append(out, *el.Value.(*Record))
		} else if j := rand.IntN(i + 1); j < n {
			out[j] = *el.Value.(*Record)
		}
		i++
	}
	// A LOOKUP reply keeps only the first records that fit, so their order must be random too.
	rand.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

// Len returns the number of live records.
func (s *Store) Len(now time.Time) int {
	s.expire(now)
	return s.order.Len()
}
