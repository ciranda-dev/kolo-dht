// Package table is the Kademlia routing table of servers, with node IDs bound to IP addresses.
package table

import (
	"bytes"
	"crypto/sha256"
	"math/bits"
	"net/netip"
	"slices"
	"time"

	kolocodec "github.com/ciranda-dev/kolo-codec"
	"github.com/ciranda-dev/kolo-dht/internal/addrs"
)

// Limits of the table.
const (
	// K is the bucket size.
	K = 20
	// MaxGroupBucket and MaxGroupTable cap the entries of one IPv4 /24 in a bucket and in the table.
	MaxGroupBucket = 2
	MaxGroupTable  = 10
	// Questionable is how long an entry may go without answering before a newcomer may take its place.
	Questionable = 15 * time.Minute
	// MaxFails is the number of failures in a row that removes an entry.
	MaxFails = 4
)

const idContext = "kolo-dht/node-id/v1"

// ID is a node ID or a lookup target.
type ID [32]byte

// NodeID returns the ID of a node at the IPv4 address ip with choice r (its low 3 bits):
// SHA-256 of the context, the 4 address bytes and r.
func NodeID(ip netip.Addr, r uint8) ID {
	b := ip.As16()
	var e kolocodec.Encoder
	e.PutFixed([]byte(idContext))
	e.PutFixed(b[12:])
	e.PutFixed([]byte{r & 7})
	return sha256.Sum256(e.Bytes())
}

// Distance returns the XOR distance between a and b.
func Distance(a, b ID) ID { return xor(a, b) }

func xor(a, b ID) (out ID) {
	for i := range out {
		out[i] = a[i] ^ b[i]
	}
	return out
}

func commonPrefix(a, b ID) int {
	for i := range a {
		if x := a[i] ^ b[i]; x != 0 {
			return i*8 + bits.LeadingZeros8(x)
		}
	}
	return len(a) * 8
}

// Entry is a server in the table.
type Entry struct {
	ID    ID
	Addr  netip.AddrPort
	R     uint8
	Seen  time.Time
	Fails int
}

// Verdict is the outcome of an insertion.
type Verdict int

// The verdicts.
const (
	// Rejected: the node is ours, unusable, over a group limit, or its bucket is full of good nodes.
	Rejected Verdict = iota
	// Added: the node is new and was added.
	Added
	// Updated: the node was present; its address and last-seen time were refreshed.
	Updated
	// Full: the bucket is full and its oldest entry is questionable; ping it, then Seen or Replace.
	Full
)

// Table holds at most K servers per bucket, in 256 buckets by common prefix length with our ID.
// Insert only nodes that answered a request we sent to their address. It is not safe for concurrent use.
type Table struct {
	self    ID
	buckets [256][]Entry
	groups  map[netip.Prefix]int
	byAddr  map[netip.AddrPort]ID
}

// New returns an empty table for our ID self.
func New(self ID) *Table {
	return &Table{self: self, groups: make(map[netip.Prefix]int), byAddr: make(map[netip.AddrPort]ID)}
}

// Self returns our ID.
func (t *Table) Self() ID { return t.self }

// SetSelf changes our ID and puts every entry in its new bucket; entries that no longer fit are dropped.
func (t *Table) SetSelf(id ID) {
	var all []Entry
	for _, b := range t.buckets {
		all = append(all, b...)
	}
	*t = *New(id)
	slices.SortFunc(all, func(a, b Entry) int { return a.Seen.Compare(b.Seen) })
	for _, e := range all {
		if v, _ := t.check(e.ID, e.Addr); v == Added {
			t.add(e)
		}
	}
}

// Len returns the number of entries.
func (t *Table) Len() int {
	n := 0
	for _, b := range t.buckets {
		n += len(b)
	}
	return n
}

func (t *Table) find(id ID) (bucket, index int) {
	b := commonPrefix(t.self, id)
	if b == len(t.buckets) {
		return -1, -1
	}
	return b, slices.IndexFunc(t.buckets[b], func(e Entry) bool { return e.ID == id })
}

// Get returns the entry with id.
func (t *Table) Get(id ID) (Entry, bool) {
	b, i := t.find(id)
	if i < 0 {
		return Entry{}, false
	}
	return t.buckets[b][i], true
}

func (t *Table) check(id ID, addr netip.AddrPort) (Verdict, int) {
	b := commonPrefix(t.self, id)
	if b == len(t.buckets) || !addrs.Usable(addr) {
		return Rejected, b
	}
	g := addrs.Group(addr.Addr())
	if t.groups[g] >= MaxGroupTable {
		return Rejected, b
	}
	inBucket := 0
	for _, e := range t.buckets[b] {
		if addrs.Group(e.Addr.Addr()) == g {
			inBucket++
		}
	}
	if inBucket >= MaxGroupBucket {
		return Rejected, b
	}
	if len(t.buckets[b]) >= K {
		return Full, b
	}
	return Added, b
}

// Check reports what Insert would do, without changing the table; use it before spending a ping on a candidate.
func (t *Table) Check(addr netip.AddrPort, r uint8, now time.Time) (Verdict, Entry) {
	id := NodeID(addr.Addr(), r)
	if _, i := t.find(id); i >= 0 {
		return Updated, Entry{}
	}
	v, b := t.check(id, addr)
	if v != Full {
		return v, Entry{}
	}
	oldest := t.buckets[b][0]
	if now.Sub(oldest.Seen) < Questionable {
		return Rejected, Entry{}
	}
	return Full, oldest
}

// Insert adds or refreshes the node at addr with choice r, seen at now, replacing another entry at addr. On Full it
// returns the bucket's oldest entry: ping it, then call Seen if it answers or Replace if not.
func (t *Table) Insert(addr netip.AddrPort, r uint8, now time.Time) (Verdict, Entry) {
	id := NodeID(addr.Addr(), r)
	if other, ok := t.byAddr[addr]; ok && other != id && addrs.Usable(addr) {
		t.Remove(other)
	}
	if b, i := t.find(id); i >= 0 {
		if !addrs.Usable(addr) {
			return Rejected, Entry{}
		}
		e := t.buckets[b][i]
		delete(t.byAddr, e.Addr)
		t.byAddr[addr] = id
		e.Addr, e.Seen, e.Fails = addr, now, 0
		t.buckets[b] = append(slices.Delete(t.buckets[b], i, i+1), e)
		return Updated, Entry{}
	}
	v, oldest := t.Check(addr, r, now)
	if v == Added {
		t.add(Entry{ID: id, Addr: addr, R: r & 7, Seen: now})
	}
	return v, oldest
}

func (t *Table) add(e Entry) {
	b := commonPrefix(t.self, e.ID)
	t.buckets[b] = append(t.buckets[b], e)
	t.groups[addrs.Group(e.Addr.Addr())]++
	t.byAddr[e.Addr] = e.ID
}

// Seen records that the entry with id answered at now: it moves to the tail of its bucket and its failures reset.
func (t *Table) Seen(id ID, now time.Time) {
	b, i := t.find(id)
	if i < 0 {
		return
	}
	e := t.buckets[b][i]
	e.Seen, e.Fails = now, 0
	t.buckets[b] = append(slices.Delete(t.buckets[b], i, i+1), e)
}

// Failed counts a request to id at addr that got no answer and reports whether the entry was removed (after MaxFails
// in a row). A failure at another address than the stored one is not counted.
func (t *Table) Failed(id ID, addr netip.AddrPort) bool {
	b, i := t.find(id)
	if i < 0 || t.buckets[b][i].Addr != addr {
		return false
	}
	t.buckets[b][i].Fails++
	if t.buckets[b][i].Fails < MaxFails {
		return false
	}
	t.remove(b, i)
	return true
}

// Remove deletes the entry with id and reports whether it was present.
func (t *Table) Remove(id ID) bool {
	b, i := t.find(id)
	if i < 0 {
		return false
	}
	t.remove(b, i)
	return true
}

func (t *Table) remove(b, i int) {
	delete(t.byAddr, t.buckets[b][i].Addr)
	g := addrs.Group(t.buckets[b][i].Addr.Addr())
	if t.groups[g]--; t.groups[g] <= 0 {
		delete(t.groups, g)
	}
	t.buckets[b] = slices.Delete(t.buckets[b], i, i+1)
}

// Replace removes old, which did not answer its ping, and inserts the node at addr with choice r.
func (t *Table) Replace(old ID, addr netip.AddrPort, r uint8, now time.Time) Verdict {
	t.Remove(old)
	v, _ := t.Insert(addr, r, now)
	return v
}

// Closest returns up to n entries ordered by XOR distance to target.
func (t *Table) Closest(target ID, n int) []Entry {
	if n <= 0 {
		return nil
	}
	var all []Entry
	for _, b := range t.buckets {
		all = append(all, b...)
	}
	slices.SortFunc(all, func(a, b Entry) int {
		da, db := xor(a.ID, target), xor(b.ID, target)
		return bytes.Compare(da[:], db[:])
	})
	return all[:min(n, len(all))]
}

// Stale returns up to n entries that have not answered for Questionable, oldest first.
func (t *Table) Stale(now time.Time, n int) []Entry {
	var out []Entry
	for _, b := range t.buckets {
		for _, e := range b {
			if now.Sub(e.Seen) >= Questionable {
				out = append(out, e)
			}
		}
	}
	slices.SortFunc(out, func(a, b Entry) int { return a.Seen.Compare(b.Seen) })
	return out[:min(n, len(out))]
}
