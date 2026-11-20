package records

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"math"
	"net/netip"
	"runtime"
	"testing"
	"time"

	koloid "github.com/ciranda-dev/kolo-id"
)

var (
	t0    = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	topic = [32]byte{1, 2, 3}
	addr  = netip.MustParseAddrPort("203.0.113.7:4000")
)

func identity(t testing.TB) *koloid.Identity {
	t.Helper()
	id, err := koloid.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func signed(t testing.TB, id *koloid.Identity, topic [32]byte, a netip.AddrPort) Record {
	t.Helper()
	r, err := Sign(id, topic, a)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// msg is Signable for an address it accepts.
func msg(t testing.TB, topic [32]byte, key [32]byte, a netip.AddrPort) []byte {
	t.Helper()
	b, err := Signable(topic, key, a)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSignable(t *testing.T) {
	var key [32]byte
	key[0] = 0xaa
	got := msg(t, topic, key, addr)
	want := append([]byte{0}, topic[:]...)
	want = append(want, key[:]...)
	want = append(want, 203, 0, 113, 7, 0xa0, 0x1f)
	if !bytes.Equal(got, want) {
		t.Fatalf("Signable = %x\nwant      %x", got, want)
	}
}

func TestSignVerify(t *testing.T) {
	id := identity(t)
	r := signed(t, id, topic, addr)
	if !bytes.Equal(r.Key[:], id.PublicKey()) || r.Topic != topic || r.Addr != addr {
		t.Fatalf("Sign filled %+v", r)
	}
	if !Verify(r) {
		t.Fatal("valid record rejected")
	}
	if !koloid.Verify(id.PublicKey(), Context, msg(t, topic, r.Key, addr), r.Sig[:]) {
		t.Fatal("signature is not Ed25519ctx under Context")
	}
	other := identity(t)
	mut := map[string]func(*Record){
		"topic": func(r *Record) { r.Topic[0] ^= 1 },
		"addr":  func(r *Record) { r.Addr = netip.MustParseAddrPort("203.0.113.7:4001") },
		"key":   func(r *Record) { copy(r.Key[:], other.PublicKey()) },
		"sig":   func(r *Record) { r.Sig[5] ^= 1 },
	}
	for name, f := range mut {
		c := r
		f(&c)
		if Verify(c) {
			t.Errorf("record with changed %s verified", name)
		}
	}
	if _, err := Sign(id, topic, netip.AddrPort{}); err == nil {
		t.Error("Sign accepted a zero address")
	}
	if _, err := Sign(nil, topic, addr); err == nil {
		t.Error("Sign accepted a nil identity")
	}
}

// TestIPv6Refused: no record is signed, verified or stored at an IPv6 address (IPv4-mapped too), even if validly signed.
func TestIPv6Refused(t *testing.T) {
	id := identity(t)
	s := NewStore(Limits{Records: 16, PerTopic: 4, PerHost: 4, PerGroup: 4, TTL: time.Minute})
	for _, a := range []string{"[2001:db8::7]:4000", "[64:ff9b::cb00:7107]:4000", "[2002:cb00:7107::1]:4000", "[::1]:4000", "[::ffff:203.0.113.7]:4000"} {
		ap := netip.MustParseAddrPort(a)
		if _, err := Sign(id, topic, ap); err == nil {
			t.Errorf("Sign accepted %s", a)
		}
		r := Record{Topic: topic, Addr: ap}
		copy(r.Key[:], id.PublicKey())
		if _, err := Signable(topic, r.Key, ap); err == nil {
			t.Errorf("Signable accepted %s", a)
		}
		// A signature over the bytes with the address left out must not verify.
		sig, err := id.Sign(Context, append(append([]byte{0}, topic[:]...), r.Key[:]...))
		if err != nil {
			t.Fatal(err)
		}
		copy(r.Sig[:], sig)
		if Verify(r) {
			t.Errorf("record at %s verified", a)
		}
		if got := s.Put(r, t0); got != Invalid {
			t.Errorf("Put(%s) = %v, want Invalid", a, got)
		}
	}
}

// smallOrderKeys are the 14 encodings crypto/ed25519 decodes to a point of order 1, 2, 4 or 8.
var smallOrderKeys = []string{
	"0000000000000000000000000000000000000000000000000000000000000000",
	"0000000000000000000000000000000000000000000000000000000000000080",
	"0100000000000000000000000000000000000000000000000000000000000000",
	"0100000000000000000000000000000000000000000000000000000000000080",
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
}

func TestSmallOrderRejected(t *testing.T) {
	// The identity point with R = identity, S = 0 verifies for every message in crypto/ed25519.
	var r Record
	r.Topic, r.Addr = topic, addr
	r.Key[0] = 1
	r.Sig[0] = 1
	if err := ed25519.VerifyWithOptions(r.Key[:], msg(t, r.Topic, r.Key, r.Addr), r.Sig[:], &ed25519.Options{Context: Context}); err != nil {
		t.Fatalf("crypto/ed25519 now rejects the forgery (%v); update this test", err)
	}
	for _, k := range smallOrderKeys {
		b, err := hex.DecodeString(k)
		if err != nil {
			t.Fatal(err)
		}
		c := r
		copy(c.Key[:], b)
		if Verify(c) {
			t.Fatalf("forged record under small-order key %s verified", k)
		}
		if got := NewStore(limits()).Put(c, t0); got != BadSignature {
			t.Fatalf("store took a record under small-order key %s: %v", k, got)
		}
	}
}

func limits() Limits {
	return Limits{Records: 100, PerTopic: 10, PerHost: 5, PerGroup: 10, TTL: time.Minute}
}

func TestPutGet(t *testing.T) {
	s := NewStore(limits())
	id := identity(t)
	r := signed(t, id, topic, addr)
	if got := s.Put(r, t0); got != Stored {
		t.Fatalf("Put = %v", got)
	}
	if got := s.Put(r, t0.Add(time.Second)); got != Refreshed {
		t.Fatalf("second Put = %v", got)
	}
	got := s.Get(topic, 10, t0.Add(2*time.Second))
	if len(got) != 1 || got[0].Key != r.Key || !got[0].Refreshed.Equal(t0.Add(time.Second)) {
		t.Fatalf("Get = %+v", got)
	}
	if f, ok := s.Find(topic, r.Key, t0); !ok || f.Addr != addr {
		t.Fatalf("Find = %+v %v", f, ok)
	}
	if len(s.Get([32]byte{9}, 10, t0)) != 0 {
		t.Error("Get of another topic not empty")
	}
}

// PutVerified does not check the signature, Put does: the caller of PutVerified must have verified the record.
func TestPutVerifiedSkipsCheck(t *testing.T) {
	r := signed(t, identity(t), topic, addr)
	if !Verify(r) {
		t.Fatal("signed record does not verify")
	}
	s := NewStore(limits())
	if got := s.PutVerified(r, t0); got != Stored {
		t.Fatalf("PutVerified of a verified record: %v", got)
	}
	if got := s.PutVerified(r, t0); got != Refreshed {
		t.Fatalf("PutVerified refresh: %v", got)
	}
	bad := r
	bad.Sig[0] ^= 1
	if got := s.Put(bad, t0); got != BadSignature {
		t.Fatalf("Put of a bad signature: %v", got)
	}
	if got := NewStore(limits()).PutVerified(bad, t0); got != Stored {
		t.Fatalf("PutVerified checked the signature: %v", got)
	}
}

func TestPutRejects(t *testing.T) {
	s := NewStore(limits())
	id := identity(t)
	r := signed(t, id, topic, addr)
	bad := r
	bad.Sig[0] ^= 1
	if got := s.Put(bad, t0); got != BadSignature {
		t.Fatalf("bad signature: %v", got)
	}
	if s.Len(t0) != 0 {
		t.Fatal("bad record stored")
	}
	s.Put(r, t0)
	// A refresh with another signature for the same key and address is checked too.
	if got := s.Put(bad, t0); got != BadSignature {
		t.Fatalf("bad refresh: %v", got)
	}
	if f, _ := s.Find(topic, r.Key, t0); f.Sig != r.Sig {
		t.Fatal("bad refresh replaced the record")
	}
	for _, a := range []string{"0.0.0.0:4000", "224.0.0.1:4000"} {
		u := Record{Topic: topic, Key: r.Key, Addr: netip.MustParseAddrPort(a)}
		sig, err := id.Sign(Context, msg(t, u.Topic, u.Key, u.Addr))
		if err != nil {
			t.Fatal(err)
		}
		copy(u.Sig[:], sig)
		if got := s.Put(u, t0); got != Invalid {
			t.Errorf("%s: %v", a, got)
		}
	}
}

func TestAddressChange(t *testing.T) {
	s := NewStore(limits())
	id := identity(t)
	s.Put(signed(t, id, topic, addr), t0)
	moved := signed(t, id, topic, netip.MustParseAddrPort("198.51.100.9:5000"))
	if got := s.Put(moved, t0.Add(time.Second)); got != Refreshed {
		t.Fatalf("move: %v", got)
	}
	if s.Len(t0) != 1 {
		t.Fatalf("Len %d after move", s.Len(t0))
	}
	if f, _ := s.Find(topic, moved.Key, t0); f.Addr != moved.Addr {
		t.Fatalf("address not updated: %v", f.Addr)
	}
	if s.hosts[hostOf(addr)] != 0 || s.hosts[hostOf(moved.Addr)] != 1 {
		t.Fatalf("host counts after move: %v", s.hosts)
	}
}

func TestLimitsRefuseNotEvict(t *testing.T) {
	l := limits()
	s := NewStore(l)
	var first []Record
	// PerHost: one host, many keys and topics.
	for i := range l.PerHost + 3 {
		r := signed(t, identity(t), [32]byte{byte(i)}, addr)
		got := s.Put(r, t0)
		if i < l.PerHost {
			if got != Stored {
				t.Fatalf("host record %d: %v", i, got)
			}
			first = append(first, r)
		} else if got != Full {
			t.Fatalf("host record %d over PerHost: %v", i, got)
		}
	}
	for _, r := range first {
		if _, ok := s.Find(r.Topic, r.Key, t0); !ok {
			t.Fatal("an earlier record was evicted")
		}
	}
	// PerTopic: many hosts, one topic.
	s = NewStore(l)
	for i := range l.PerTopic + 3 {
		a := netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, byte(i), 1}), 4000)
		got := s.Put(signed(t, identity(t), topic, a), t0)
		if want := Stored; i >= l.PerTopic {
			want = Full
			if got != want {
				t.Fatalf("topic record %d: %v, want %v", i, got, want)
			}
		} else if got != want {
			t.Fatalf("topic record %d: %v, want %v", i, got, want)
		}
	}
	l.Records = 7
	s = NewStore(l)
	for i := range 10 {
		a := netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, byte(i), 1}), 4000)
		got := s.Put(signed(t, identity(t), [32]byte{byte(i)}, a), t0)
		if (i < 7) != (got == Stored) {
			t.Fatalf("record %d: %v", i, got)
		}
	}
	if s.Len(t0) != 7 {
		t.Fatalf("Len %d, want 7", s.Len(t0))
	}
}

func TestExpiry(t *testing.T) {
	l := limits()
	l.PerHost = 1
	s := NewStore(l)
	a := signed(t, identity(t), topic, addr)
	s.Put(a, t0)
	if got := len(s.Get(topic, 10, t0.Add(l.TTL-time.Millisecond))); got != 1 {
		t.Fatalf("record gone before TTL: %d", got)
	}
	if got := len(s.Get(topic, 10, t0.Add(l.TTL))); got != 0 {
		t.Fatalf("record alive at TTL: %d", got)
	}
	if _, ok := s.Find(topic, a.Key, t0.Add(l.TTL)); ok {
		t.Fatal("Find returned an expired record")
	}
	b := signed(t, identity(t), topic, addr)
	if got := s.Put(b, t0.Add(l.TTL)); got != Stored {
		t.Fatalf("Put after expiry: %v", got)
	}
	s.Put(b, t0.Add(l.TTL+30*time.Second))
	if _, ok := s.Find(topic, b.Key, t0.Add(2*l.TTL+10*time.Second)); !ok {
		t.Fatal("refreshed record expired")
	}
	if s.Len(t0.Add(10*l.TTL)) != 0 || len(s.hosts) != 0 || len(s.topics) != 0 {
		t.Fatalf("state left after expiry: %d hosts, %d topics", len(s.hosts), len(s.topics))
	}
}

func TestGetSample(t *testing.T) {
	l := limits()
	l.PerTopic = 30
	s := NewStore(l)
	keys := map[[32]byte]bool{}
	for i := range 20 {
		a := netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, byte(i), 1}), 4000)
		r := signed(t, identity(t), topic, a)
		s.Put(r, t0)
		keys[r.Key] = true
	}
	seen := map[[32]byte]bool{}
	for range 200 {
		got := s.Get(topic, 3, t0)
		if len(got) != 3 {
			t.Fatalf("Get(3) returned %d", len(got))
		}
		for _, r := range got {
			if !keys[r.Key] {
				t.Fatal("Get returned an unknown record")
			}
			seen[r.Key] = true
		}
	}
	if len(seen) != len(keys) {
		t.Fatalf("200 samples of 3 saw %d of %d records", len(seen), len(keys))
	}
}

// TestOldContextRefused: a signature under the v0 context does not verify.
func TestOldContextRefused(t *testing.T) {
	id := identity(t)
	r := signed(t, id, topic, addr)
	sig, err := id.Sign("kolo-dht/announce/v0", msg(t, topic, r.Key, addr))
	if err != nil {
		t.Fatal(err)
	}
	copy(r.Sig[:], sig)
	if Verify(r) {
		t.Fatal("a v0 signature verified")
	}
}

// TestPerHostIsPerAddress: PerHost counts one IPv4 address, not its /24.
func TestPerHostIsPerAddress(t *testing.T) {
	s := NewStore(limits())
	for i := range 2 * limits().PerHost {
		a := netip.AddrPortFrom(netip.AddrFrom4([4]byte{203, 0, 113, byte(10 + i)}), 4000)
		if got := s.Put(signed(t, identity(t), [32]byte{byte(i)}, a), t0); got != Stored {
			t.Fatalf("record %d from its own address: %v", i, got)
		}
	}
}

// TestGetAllocates: Get of 16 records out of 512 copies only what it returns.
func TestGetAllocates(t *testing.T) {
	s := NewStore(Limits{Records: 1024, PerTopic: 512, PerHost: 512, PerGroup: 512, TTL: time.Hour})
	for i := range 512 {
		a := netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 18 + byte(i>>8), byte(i), 1}), 4000)
		if got := s.Put(signed(t, identity(t), topic, a), t0); got != Stored {
			t.Fatalf("Put %d: %v", i, got)
		}
	}
	res := testing.Benchmark(func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			if len(s.Get(topic, 16, t0)) != 16 {
				b.Fatal("short Get")
			}
		}
	})
	if got := res.AllocedBytesPerOp(); got > 4096 {
		t.Fatalf("Get allocates %d bytes per call", got)
	}
}

// TestPerGroup: one /24 holds at most PerGroup records of a topic, also by moving a record there; other topics and
// other /24s are not affected.
func TestPerGroup(t *testing.T) {
	s := NewStore(Limits{Records: 100, PerTopic: 10, PerHost: 10, PerGroup: 2, TTL: time.Minute})
	in := func(i byte) netip.AddrPort { return netip.AddrPortFrom(netip.AddrFrom4([4]byte{203, 0, 113, i}), 4000) }
	for i := range byte(2) {
		if got := s.Put(signed(t, identity(t), topic, in(1+i)), t0); got != Stored {
			t.Fatalf("record %d: %v", i, got)
		}
	}
	if got := s.Put(signed(t, identity(t), topic, in(3)), t0); got != Full {
		t.Fatalf("third record from one /24: %v, want Full", got)
	}
	if got := s.Put(signed(t, identity(t), [32]byte{9}, in(3)), t0); got != Stored {
		t.Fatalf("another topic: %v", got)
	}
	id := identity(t)
	if got := s.Put(signed(t, id, topic, netip.MustParseAddrPort("198.51.100.1:4000")), t0); got != Stored {
		t.Fatalf("another /24: %v", got)
	}
	if got := s.Put(signed(t, id, topic, in(4)), t0); got != Full {
		t.Fatalf("moving into a full /24: %v, want Full", got)
	}
	if s.Len(t0.Add(time.Minute)) != 0 || len(s.groups) != 0 {
		t.Fatalf("counts left after expiry: %v", s.groups)
	}
}

// heapPerRecord is the documented worst-case heap of one stored record (config.go, README).
const heapPerRecord = 710

// TestHeapPerRecord fills a store in the worst case, each record in its own topic, address and /24, and checks the
// heap each record takes against the documented figure, with a 5% margin.
func TestHeapPerRecord(t *testing.T) {
	if testing.Short() {
		t.Skip("signs 8192 records")
	}
	const n = 8192
	id := identity(t)
	recs := make([]Record, n)
	for i := range recs {
		recs[i] = signed(t, id, [32]byte{byte(i), byte(i >> 8)}, netip.AddrPortFrom(netip.AddrFrom4([4]byte{11, byte(i >> 8), byte(i), 1}), 4000))
	}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	s := NewStore(Limits{Records: n, PerTopic: 1, PerHost: 1, PerGroup: 1, TTL: time.Hour})
	for _, r := range recs {
		if got := s.Put(r, t0); got != Stored {
			t.Fatalf("Put: %v", got)
		}
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	per := float64(after.HeapAlloc-before.HeapAlloc) / n
	t.Logf("%.0f heap bytes per record", per)
	if per > heapPerRecord*1.05 {
		t.Fatalf("%.0f heap bytes per record, documented %d", per, heapPerRecord)
	}
	runtime.KeepAlive(s)
}

// fill stores k records of topic, each from its own /24, and returns their keys in order.
func fill(t *testing.T, s *Store, k int) [][32]byte {
	t.Helper()
	keys := make([][32]byte, k)
	for i := range k {
		r := signed(t, identity(t), topic, netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, byte(i), 1}), 4000))
		if got := s.Put(r, t0); got != Stored {
			t.Fatalf("Put %d: %v", i, got)
		}
		keys[i] = r.Key
	}
	return keys
}

// uniform fails if any count is more than 5 sigma from calls x p.
func uniform(t *testing.T, counts map[[32]byte]int, keys [][32]byte, calls int, p float64) {
	t.Helper()
	mean, sigma := float64(calls)*p, math.Sqrt(float64(calls)*p*(1-p))
	for i, k := range keys {
		if d := math.Abs(float64(counts[k]) - mean); d > 5*sigma {
			t.Fatalf("record %d chosen %d times, want %.0f ± %.0f", i, counts[k], mean, 5*sigma)
		}
	}
}

// TestGetFrequency: Get(3) picks each record with probability 3/k. With 4 records the map's iteration order is far
// from uniform (it starts at a random one of 8 slots), so a reservoir that favors early or late records shows.
func TestGetFrequency(t *testing.T) {
	for _, k := range []int{64, 4} {
		s := NewStore(Limits{Records: 100, PerTopic: 64, PerHost: 1, PerGroup: 1, TTL: time.Hour})
		keys := fill(t, s, k)
		const calls = 64_000
		counts := map[[32]byte]int{}
		for range calls {
			for _, r := range s.Get(topic, 3, t0) {
				counts[r.Key]++
			}
		}
		uniform(t, counts, keys, calls, 3/float64(k))
	}
}

// TestGetPrefixUniform: Get returns its sample in random order, so the 9 to 11 records a LOOKUP reply keeps are a
// uniform choice too.
func TestGetPrefixUniform(t *testing.T) {
	s := NewStore(Limits{Records: 100, PerTopic: 16, PerHost: 1, PerGroup: 1, TTL: time.Hour})
	keys := fill(t, s, 16)
	const calls = 20_000
	counts := map[[32]byte]int{}
	for range calls {
		for _, r := range s.Get(topic, 16, t0)[:9] {
			counts[r.Key]++
		}
	}
	uniform(t, counts, keys, calls, 9.0/16)
}

// TestMoveFreesGroup: a record that moves to another /24 frees its place in the old one.
func TestMoveFreesGroup(t *testing.T) {
	s := NewStore(Limits{Records: 100, PerTopic: 10, PerHost: 10, PerGroup: 2, TTL: time.Minute})
	in := func(i byte) netip.AddrPort { return netip.AddrPortFrom(netip.AddrFrom4([4]byte{203, 0, 113, i}), 4000) }
	id := identity(t)
	if got := s.Put(signed(t, id, topic, in(1)), t0); got != Stored {
		t.Fatalf("first: %v", got)
	}
	if got := s.Put(signed(t, id, topic, netip.MustParseAddrPort("198.51.100.1:4000")), t0); got != Refreshed {
		t.Fatalf("move: %v", got)
	}
	for i := range byte(2) {
		if got := s.Put(signed(t, identity(t), topic, in(10+i)), t0); got != Stored {
			t.Fatalf("record %d in the /24 the record left: %v", i, got)
		}
	}
}

// TestPortChangeInFullGroup: a new port at the same address, in a full /24, is a refresh.
func TestPortChangeInFullGroup(t *testing.T) {
	s := NewStore(Limits{Records: 100, PerTopic: 10, PerHost: 1, PerGroup: 2, TTL: time.Minute})
	id := identity(t)
	s.Put(signed(t, id, topic, netip.MustParseAddrPort("203.0.113.1:4000")), t0)
	s.Put(signed(t, identity(t), topic, netip.MustParseAddrPort("203.0.113.2:4000")), t0)
	if got := s.Put(signed(t, id, topic, netip.MustParseAddrPort("203.0.113.1:4001")), t0); got != Refreshed {
		t.Fatalf("port change: %v, want Refreshed", got)
	}
	if len(s.hosts) != 2 || s.groups[groupOf(topic, netip.MustParseAddrPort("203.0.113.1:1"))] != 2 {
		t.Fatalf("counts after the port change: %v %v", s.hosts, s.groups)
	}
}

// TestRefreshTakesSecret: a refresh with the stored address and signature keeps its new share and secret, so a
// storer authenticates PUNCH with the secret of the announcer's latest ANNOUNCE.
func TestRefreshTakesSecret(t *testing.T) {
	s := NewStore(limits())
	r := signed(t, identity(t), topic, addr)
	r.Share, r.Secret = [32]byte{1}, [32]byte{2}
	s.Put(r, t0)
	r.Share, r.Secret = [32]byte{3}, [32]byte{4}
	if got := s.Put(r, t0.Add(time.Second)); got != Refreshed {
		t.Fatalf("Put = %v", got)
	}
	if f, _ := s.Find(topic, r.Key, t0.Add(time.Second)); f.Share != r.Share || f.Secret != r.Secret {
		t.Fatalf("after refresh: share %x secret %x", f.Share[:1], f.Secret[:1])
	}
}
