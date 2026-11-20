package table

import (
	"bytes"
	"encoding/hex"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/ciranda-dev/kolo-dht/internal/addrs"
)

var t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func ap(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

// v4 returns a distinct public address in its own /24 for each i.
func v4(i int) netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{byte(11 + i>>16), byte(i >> 8), byte(i), 1}), 4000)
}

func TestNodeID(t *testing.T) {
	a := netip.MustParseAddr("203.0.113.7")
	if x, y := NodeID(a, 1), NodeID(a, 1); x != y {
		t.Fatal("NodeID is not deterministic")
	}
	seen := map[ID]bool{}
	for r := range uint8(8) {
		seen[NodeID(a, r)] = true
	}
	if len(seen) != 8 {
		t.Fatalf("%d distinct IDs for 8 choices of r", len(seen))
	}
	if NodeID(a, 8) != NodeID(a, 0) {
		t.Error("r above 7 gives an extra ID")
	}
	if NodeID(a, 0) == NodeID(netip.MustParseAddr("203.0.113.8"), 0) {
		t.Error("two IPv4 addresses share an ID")
	}
}

func TestBucketIndex(t *testing.T) {
	var a, b ID
	if got := commonPrefix(a, b); got != 256 {
		t.Fatalf("equal IDs: %d", got)
	}
	b[0] = 0x80
	if got := commonPrefix(a, b); got != 0 {
		t.Fatalf("first bit differs: %d", got)
	}
	b[0], b[31] = 0, 1
	if got := commonPrefix(a, b); got != 255 {
		t.Fatalf("last bit differs: %d", got)
	}
	b[31], b[2] = 0, 0x10
	if got := commonPrefix(a, b); got != 19 {
		t.Fatalf("bit 19 differs: %d", got)
	}
}

func TestInsert(t *testing.T) {
	self := NodeID(netip.MustParseAddr("198.51.100.1"), 0)
	tb := New(self)
	if v, _ := tb.Insert(ap("203.0.113.7:4000"), 2, t0); v != Added {
		t.Fatalf("first insert: %v", v)
	}
	if v, _ := tb.Insert(ap("203.0.113.7:5000"), 2, t0.Add(time.Second)); v != Updated {
		t.Fatalf("same node, new port: %v", v)
	}
	e, ok := tb.Get(NodeID(netip.MustParseAddr("203.0.113.7"), 2))
	if !ok || e.Addr.Port() != 5000 || !e.Seen.Equal(t0.Add(time.Second)) || e.R != 2 {
		t.Fatalf("entry after update: %+v %v", e, ok)
	}
	if v, _ := tb.Insert(ap("198.51.100.1:4000"), 0, t0); v != Rejected {
		t.Errorf("own ID: %v", v)
	}
	for _, bad := range []string{"0.0.0.0:4000", "224.0.0.1:4000", "203.0.113.9:0"} {
		if v, _ := tb.Insert(ap(bad), 0, t0); v != Rejected {
			t.Errorf("%s: %v", bad, v)
		}
	}
	if tb.Len() != 1 {
		t.Errorf("Len = %d, want 1", tb.Len())
	}
}

func TestDiversity(t *testing.T) {
	tb := New(NodeID(netip.MustParseAddr("198.51.100.1"), 0))
	perBucket := map[int]int{}
	added := 0
	for host := range 256 {
		r := uint8(host % 8)
		a := netip.AddrPortFrom(netip.AddrFrom4([4]byte{203, 0, 113, byte(host)}), 4000)
		if v, _ := tb.Insert(a, r, t0); v == Added {
			added++
			perBucket[commonPrefix(tb.self, NodeID(a.Addr(), r))]++
		}
	}
	if added != MaxGroupTable {
		t.Fatalf("added %d from one /24, want %d", added, MaxGroupTable)
	}
	for b, n := range perBucket {
		if n > MaxGroupBucket {
			t.Fatalf("bucket %d has %d from one /24", b, n)
		}
	}
	// kolo-dht is IPv4 only: no IPv6 address enters the table.
	for _, s := range []string{"[2001:db8:7::1]:4000", "[64:ff9b::cb00:7101]:4000", "[::1]:4000", "[::ffff:198.51.100.200]:4000"} {
		if v, _ := tb.Insert(netip.MustParseAddrPort(s), 1, t0); v != Rejected {
			t.Fatalf("Insert(%s) = %v, want Rejected", s, v)
		}
	}
	var victim Entry
	for _, e := range tb.Closest(ID{}, tb.Len()) {
		if addrs.Group(e.Addr.Addr()) == netip.MustParsePrefix("203.0.113.0/24") {
			victim = e
			break
		}
	}
	if !tb.Remove(victim.ID) {
		t.Fatal("Remove failed")
	}
	got := false
	for host := range 256 {
		a := netip.AddrPortFrom(netip.AddrFrom4([4]byte{203, 0, 113, byte(host)}), 4001)
		if v, _ := tb.Insert(a, uint8(host%8), t0); v == Added {
			got = true
		}
	}
	if !got {
		t.Error("group slot not freed by Remove")
	}
}

// fillBucket0 inserts nodes from distinct /24s until bucket 0 holds K; it returns them in insertion order.
func fillBucket0(t *testing.T, tb *Table, now time.Time) []netip.AddrPort {
	t.Helper()
	var in []netip.AddrPort
	for i := 0; len(in) < K; i++ {
		a := v4(i)
		if commonPrefix(tb.self, NodeID(a.Addr(), 0)) != 0 {
			continue
		}
		if v, _ := tb.Insert(a, 0, now.Add(time.Duration(len(in))*time.Second)); v != Added {
			t.Fatalf("insert %d: %v", len(in), v)
		}
		in = append(in, a)
	}
	return in
}

func nextForBucket0(tb *Table, skip int) netip.AddrPort {
	for i := skip; ; i++ {
		a := v4(i)
		if _, ok := tb.Get(NodeID(a.Addr(), 0)); !ok && commonPrefix(tb.self, NodeID(a.Addr(), 0)) == 0 {
			return a
		}
	}
}

func TestFullBucketKeepsGoodNodes(t *testing.T) {
	tb := New(ID{})
	in := fillBucket0(t, tb, t0)
	newcomer := nextForBucket0(tb, 100000)
	if v, _ := tb.Insert(newcomer, 0, t0.Add(time.Minute)); v != Rejected {
		t.Fatalf("full bucket of good nodes: %v, want Rejected", v)
	}
	for i := range 1000 {
		tb.Insert(nextForBucket0(tb, 200000+i*7), 0, t0.Add(time.Minute))
	}
	for _, a := range in {
		if _, ok := tb.Get(NodeID(a.Addr(), 0)); !ok {
			t.Fatalf("good node %s evicted", a)
		}
	}
}

func TestPingTheOldest(t *testing.T) {
	tb := New(ID{})
	in := fillBucket0(t, tb, t0)
	later := t0.Add(Questionable + time.Hour)
	newcomer := nextForBucket0(tb, 100000)
	v, oldest := tb.Insert(newcomer, 0, later)
	if v != Full || oldest.Addr != in[0] {
		t.Fatalf("got %v %s, want Full with the oldest %s", v, oldest.Addr, in[0])
	}
	if c, _ := tb.Check(newcomer, 0, later); c != Full {
		t.Fatalf("Check = %v, want Full", c)
	}
	// The oldest answers: it stays, moves to the tail, and the next oldest is offered.
	tb.Seen(oldest.ID, later)
	v, next := tb.Insert(newcomer, 0, later)
	if v != Full || next.Addr != in[1] {
		t.Fatalf("after Seen: %v %s, want Full with %s", v, next.Addr, in[1])
	}
	// The next oldest does not answer: the newcomer replaces it.
	if v := tb.Replace(next.ID, newcomer, 0, later); v != Added {
		t.Fatalf("Replace: %v", v)
	}
	if _, ok := tb.Get(next.ID); ok {
		t.Error("replaced node still present")
	}
	if _, ok := tb.Get(NodeID(newcomer.Addr(), 0)); !ok {
		t.Error("newcomer missing after Replace")
	}
	if _, ok := tb.Get(oldest.ID); !ok {
		t.Error("node that answered was evicted")
	}
}

func TestCheckDoesNotModify(t *testing.T) {
	tb := New(ID{})
	if v, _ := tb.Check(ap("203.0.113.7:4000"), 0, t0); v != Added {
		t.Fatalf("Check = %v, want Added", v)
	}
	if tb.Len() != 0 {
		t.Fatal("Check inserted")
	}
}

func TestFailed(t *testing.T) {
	tb := New(ID{})
	a := ap("203.0.113.7:4000")
	tb.Insert(a, 0, t0)
	id := NodeID(a.Addr(), 0)
	for i := 1; i < MaxFails; i++ {
		if tb.Failed(id, a) {
			t.Fatalf("removed after %d failures", i)
		}
	}
	tb.Seen(id, t0)
	for i := 1; i < MaxFails; i++ {
		if tb.Failed(id, a) {
			t.Fatal("Seen did not reset failures")
		}
	}
	if !tb.Failed(id, a) {
		t.Fatalf("not removed after %d failures in a row", MaxFails)
	}
	if tb.Len() != 0 {
		t.Fatal("Len after removal")
	}
}

func TestClosest(t *testing.T) {
	tb := New(NodeID(netip.MustParseAddr("198.51.100.1"), 0))
	for i := range 500 {
		tb.Insert(v4(i), uint8(i%8), t0)
	}
	target := NodeID(netip.MustParseAddr("192.0.2.1"), 3)
	got := tb.Closest(target, K)
	all := tb.Closest(target, tb.Len())
	if len(got) != K || len(all) != tb.Len() {
		t.Fatalf("Closest returned %d and %d entries", len(got), len(all))
	}
	ids := make([]ID, 0, tb.Len())
	for _, e := range all {
		ids = append(ids, e.ID)
	}
	slices.SortFunc(ids, func(a, b ID) int {
		da, db := xor(a, target), xor(b, target)
		return bytes.Compare(da[:], db[:])
	})
	for i := range got {
		if got[i].ID != ids[i] {
			t.Fatalf("entry %d is not the %d-th closest", i, i)
		}
	}
	if len(tb.Closest(target, 0)) != 0 {
		t.Error("Closest(0) not empty")
	}
}

func TestStale(t *testing.T) {
	tb := New(ID{})
	tb.Insert(v4(1), 0, t0)
	tb.Insert(v4(2), 0, t0.Add(10*time.Minute))
	tb.Insert(v4(3), 0, t0.Add(20*time.Minute))
	now := t0.Add(26 * time.Minute)
	st := tb.Stale(now, 10)
	if len(st) != 2 || st[0].Addr != v4(1) || st[1].Addr != v4(2) {
		t.Fatalf("Stale = %v", st)
	}
	if len(tb.Stale(now, 1)) != 1 {
		t.Error("Stale ignores its limit")
	}
}

func TestSetSelf(t *testing.T) {
	tb := New(ID{})
	for i := range 300 {
		tb.Insert(v4(i), 0, t0)
	}
	n := tb.Len()
	newSelf := NodeID(netip.MustParseAddr("192.0.2.9"), 1)
	tb.SetSelf(newSelf)
	if tb.Self() != newSelf {
		t.Fatal("Self not changed")
	}
	if tb.Len() == 0 || tb.Len() > n {
		t.Fatalf("Len %d after SetSelf, was %d", tb.Len(), n)
	}
	for _, e := range tb.Closest(ID{}, tb.Len()) {
		b := commonPrefix(newSelf, e.ID)
		if !slices.ContainsFunc(tb.buckets[b], func(x Entry) bool { return x.ID == e.ID }) {
			t.Fatalf("entry %s not in bucket %d after SetSelf", e.Addr, b)
		}
	}
}

func TestBounded(t *testing.T) {
	tb := New(ID{})
	for i := range 20000 {
		tb.Insert(v4(i), uint8(i%8), t0)
	}
	if tb.Len() > 256*K {
		t.Fatalf("Len %d over %d", tb.Len(), 256*K)
	}
	for b, bucket := range tb.buckets {
		if len(bucket) > K {
			t.Fatalf("bucket %d holds %d", b, len(bucket))
		}
	}
}

func TestOneEntryPerAddress(t *testing.T) {
	tb := New(ID{})
	a := ap("203.0.113.7:4000")
	tb.Insert(a, 1, t0)
	// The node at a now uses another r: its old entry goes.
	if v, _ := tb.Insert(a, 2, t0); v != Added {
		t.Fatalf("new r: %v", v)
	}
	if tb.Len() != 1 {
		t.Fatalf("Len %d, want 1", tb.Len())
	}
	if _, ok := tb.Get(NodeID(a.Addr(), 1)); ok {
		t.Fatal("old entry kept")
	}
	// An entry that moves to a port another entry holds takes its place.
	b := ap("203.0.113.7:5000")
	tb.Insert(b, 3, t0)
	tb.Insert(b, 2, t0)
	if tb.Len() != 1 {
		t.Fatalf("Len %d after a move, want 1", tb.Len())
	}
	if e, ok := tb.Get(NodeID(a.Addr(), 2)); !ok || e.Addr != b {
		t.Fatalf("moved entry %+v %v", e, ok)
	}
	if tb.Remove(NodeID(a.Addr(), 2)); len(tb.byAddr) != 0 {
		t.Fatalf("address index left %d entries", len(tb.byAddr))
	}
}

func TestFailedOnlyAtStoredAddress(t *testing.T) {
	tb := New(ID{})
	a := ap("203.0.113.7:1000")
	tb.Insert(a, 4, t0)
	id := NodeID(a.Addr(), 4)
	for range 5 {
		if tb.Failed(id, ap("203.0.113.7:2000")) {
			t.Fatal("removed by failures at another port")
		}
	}
	if e, ok := tb.Get(id); !ok || e.Fails != 0 {
		t.Fatalf("entry %+v %v", e, ok)
	}
	for range MaxFails - 1 {
		tb.Failed(id, a)
	}
	if !tb.Failed(id, a) {
		t.Fatal("not removed by failures at its own address")
	}
}

// TestNodeIDVector pins NodeID to SHA-256("kolo-dht/node-id/v1" ‖ 203.0.113.7 ‖ 5).
func TestNodeIDVector(t *testing.T) {
	want := "e12e54330cba9965d5dc02fefc7968b16a9ed67e5c75eff24b83839e938ea52a"
	if got := NodeID(netip.MustParseAddr("203.0.113.7"), 5); hex.EncodeToString(got[:]) != want {
		t.Fatalf("NodeID = %x, want %s", got, want)
	}
}
