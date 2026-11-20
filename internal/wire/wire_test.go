package wire

import (
	"bytes"
	"errors"
	"net/netip"
	"reflect"
	"testing"
)

func fill(b byte) (out [32]byte) {
	for i := range out {
		out[i] = b
	}
	return out
}

func sig(b byte) (out [SigSize]byte) {
	for i := range out {
		out[i] = b
	}
	return out
}

var (
	v4   = netip.MustParseAddrPort("203.0.113.7:4000")
	v4b  = netip.MustParseAddrPort("198.51.100.9:65535")
	pid  = [PunchIDSize]byte{1, 2, 3, 4, 5, 6, 7, 8}
	flag = NewFlags(5, true)
)

func samples() []Message {
	nodes := []Node{{NewFlags(0, true), v4}, {NewFlags(7, true), v4b}}
	recs := []Record{{Key: fill(9), Addr: v4, Age: 3, Sig: sig(8)}, {Key: fill(10), Addr: v4b, Age: 65535, Sig: sig(7)}}
	return []Message{
		&Ping{Flags: flag},
		&PingReply{Observed: v4, Token: fill(1), Flags: flag},
		&FindNode{Flags: flag, Target: fill(2)},
		&FindNodeReply{Observed: v4b, Token: fill(1), Flags: flag, Nodes: nodes},
		&FindNodeReply{Observed: v4b, Token: fill(1), Flags: flag},
		&Lookup{Flags: flag, Topic: fill(3)},
		&LookupReply{Observed: v4, Token: fill(1), Flags: flag, Nodes: nodes, Records: recs},
		&LookupReply{Observed: v4, Token: fill(1), Flags: flag},
		&Announce{Flags: flag, Token: fill(1), Topic: fill(3), Key: fill(4), Addr: v4, Sig: sig(5), Share: fill(6)},
		&AnnounceReply{Observed: v4, Token: fill(1), Status: StatusFull, Share: fill(7)},
		&Connect{Flags: flag, Token: fill(1), Topic: fill(3), Target: fill(4), Key: fill(5), Class: ClassRandom, PunchID: pid},
		&Connect{Flags: flag, Token: fill(1), Topic: fill(3), Target: fill(4), Key: fill(5), Class: ClassConsistent, NoRandom: true, PunchID: pid},
		&ConnectReply{Observed: v4b, Token: fill(1), Status: StatusOK, Class: ClassConsistent, Sig: sig(6)},
		&ConnectReply{Observed: v4b, Token: fill(1), Status: StatusFull},
		&Punch{Flags: flag, Topic: fill(3), Target: fill(4), Key: fill(5), Addr: v4b, Class: ClassUnknown, PunchID: pid, Counter: 1<<63 + 5, MAC: fill(8)},
		&Punch{Flags: flag, Topic: fill(3), Target: fill(4), Key: fill(5), Addr: v4b, Class: ClassConsistent, NoRandom: true, PunchID: pid, Counter: 1, MAC: fill(8)},
		&PunchReply{Status: StatusUnreachable, Class: ClassRandom},
		&PunchReply{Status: StatusOK, Class: ClassRandom, Sig: sig(4)},
		&Probe{PunchID: pid, Nonce: [8]byte{9}, Echo: [8]byte{1, 1}},
		&Probe{PunchID: pid},
	}
}

// TestStatusValues pins the wire values of the statuses; TryLater (7) is the last one.
func TestStatusValues(t *testing.T) {
	got := []Status{StatusOK, StatusBadToken, StatusFull, StatusNotServer, StatusNoRecord, StatusUnreachable, StatusRefused, StatusTryLater}
	for i, s := range got {
		if int(s) != i {
			t.Errorf("status %d has value %d", i, s)
		}
	}
	if maxStatus != StatusTryLater {
		t.Fatalf("maxStatus = %d, want TryLater", maxStatus)
	}
	for _, m := range []Message{
		&PunchReply{Status: StatusTryLater, Class: ClassConsistent},
		&ConnectReply{Observed: v4b, Token: fill(1), Status: StatusTryLater, Class: ClassRandom},
	} {
		b, err := Encode(3, m, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, got, err := Decode(b); err != nil || !reflect.DeepEqual(normalize(got), normalize(m)) {
			t.Fatalf("round trip of %+v: %+v, %v", m, got, err)
		}
	}
	b := encodeRaw(TypePunchReply, func(e *enc) { e.PutUvarint(8); e.PutUvarint(0) })
	if _, _, err := Decode(b); err == nil {
		t.Fatal("status 8 decoded")
	}
}

func TestRoundTrip(t *testing.T) {
	for _, m := range samples() {
		for _, size := range []int{0, MaxSize} {
			b, err := Encode(42, m, size)
			if err != nil {
				t.Fatalf("Encode(%T, %d): %v", m, size, err)
			}
			id, got, err := Decode(b)
			if err != nil {
				t.Fatalf("Decode(%T, %d): %v", m, size, err)
			}
			if id != 42 || !reflect.DeepEqual(normalize(got), normalize(m)) {
				t.Fatalf("round trip of %T: got %d %+v, want %+v", m, id, got, m)
			}
		}
	}
}

// normalize treats nil and empty lists as equal.
func normalize(m Message) Message {
	switch m := m.(type) {
	case *FindNodeReply:
		c := *m
		if len(c.Nodes) == 0 {
			c.Nodes = nil
		}
		return &c
	case *LookupReply:
		c := *m
		if len(c.Nodes) == 0 {
			c.Nodes = nil
		}
		if len(c.Records) == 0 {
			c.Records = nil
		}
		return &c
	}
	return m
}

func TestTypes(t *testing.T) {
	want := []Type{TypePing, TypePingReply, TypeFindNode, TypeFindNodeReply, TypeFindNodeReply, TypeLookup, TypeLookupReply, TypeLookupReply,
		TypeAnnounce, TypeAnnounceReply, TypeConnect, TypeConnect, TypeConnectReply, TypeConnectReply, TypePunch, TypePunch,
		TypePunchReply, TypePunchReply, TypeProbe, TypeProbe}
	for i, m := range samples() {
		if m.Type() != want[i] {
			t.Errorf("%T.Type() = %d, want %d", m, m.Type(), want[i])
		}
	}
	for _, req := range []Type{TypePing, TypeFindNode, TypeLookup, TypeAnnounce, TypeConnect, TypePunch} {
		if !IsRequest(req) || IsRequest(ReplyType(req)) || ReplyType(req) != req+1 {
			t.Errorf("request type %d: IsRequest or ReplyType wrong", req)
		}
	}
	if IsRequest(TypeProbe) {
		t.Error("PROBE is a request")
	}
}

func TestPadding(t *testing.T) {
	m := &Ping{Flags: flag}
	min, err := Encode(1, m, 0)
	if err != nil {
		t.Fatal(err)
	}
	for size := len(min); size <= MaxSize; size++ {
		b, err := Encode(1, m, size)
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		if len(b) > size || len(b) < size-1 {
			t.Fatalf("Encode to %d gave %d bytes", size, len(b))
		}
		if _, _, err := Decode(b); err != nil {
			t.Fatalf("size %d: padded message does not decode: %v", size, err)
		}
	}
	if _, err := Encode(1, m, len(min)-1); !errors.Is(err, ErrTooLarge) {
		t.Errorf("Encode below its own size: %v, want ErrTooLarge", err)
	}
	if _, err := Encode(1, m, MaxSize+1); !errors.Is(err, ErrTooLarge) {
		t.Errorf("Encode above MaxSize: %v, want ErrTooLarge", err)
	}
}

func TestDecodeRejects(t *testing.T) {
	good, err := Encode(7, &Ping{Flags: flag}, 0)
	if err != nil {
		t.Fatal(err)
	}
	padded, err := Encode(7, &Ping{Flags: flag}, 64)
	if err != nil {
		t.Fatal(err)
	}
	nonzero := bytes.Clone(padded)
	nonzero[len(nonzero)-1] = 1
	marker := bytes.Clone(good)
	marker[0] = 0x40
	unknown := append([]byte{Marker, 14}, good[2:]...)
	zeroType := append([]byte{Marker, 0}, good[2:]...)
	tests := map[string][]byte{
		"empty":            {},
		"marker only":      {Marker},
		"wrong marker":     marker,
		"unknown type":     unknown,
		"type zero":        zeroType,
		"truncated":        good[:len(good)-1],
		"trailing":         append(bytes.Clone(good), 0),
		"nonzero padding":  nonzero,
		"too large":        append(bytes.Clone(good), make([]byte, MaxSize)...),
		"flags out of use": encodeRaw(TypePing, func(e *enc) { e.PutUvarint(0x10) }),
		"port zero": encodeRaw(TypePingReply, func(e *enc) {
			e.PutFixed([]byte{203, 0, 113, 7})
			e.PutUvarint(0)
			e.PutFixed(make([]byte, 32))
			e.PutUvarint(0)
		}),
		"port too large": encodeRaw(TypePingReply, func(e *enc) {
			e.PutFixed([]byte{203, 0, 113, 7})
			e.PutUvarint(65536)
			e.PutFixed(make([]byte, 32))
			e.PutUvarint(0)
		}),
		"status out of range": encodeRaw(TypePunchReply, func(e *enc) { e.PutUvarint(uint64(maxStatus) + 1); e.PutUvarint(0) }),
		"class out of range":  encodeRaw(TypePunchReply, func(e *enc) { e.PutUvarint(0); e.PutUvarint(uint64(maxClass) + 1) }),
		"no signature":        encodeRaw(TypePunchReply, func(e *enc) { e.PutUvarint(0); e.PutUvarint(0) }),
		"NoRandom out of range": encodeRaw(TypeConnect, func(e *enc) {
			e.PutUvarint(0)
			e.PutFixed(make([]byte, 4*32))
			e.PutUvarint(0)
			e.PutUvarint(2)
			e.PutFixed(make([]byte, 8))
		}),
		"too many nodes": encodeRaw(TypeFindNodeReply, func(e *enc) {
			PutAddr(e, v4)
			e.PutFixed(make([]byte, 32))
			e.PutUvarint(0)
			e.PutUvarint(MaxNodes + 1)
		}),
		"record age too large": encodeRaw(TypeLookupReply, func(e *enc) {
			PutAddr(e, v4)
			e.PutFixed(make([]byte, 32))
			e.PutUvarint(0)
			e.PutUvarint(0)
			e.PutUvarint(1)
			e.PutFixed(make([]byte, 32))
			PutAddr(e, v4)
			e.PutUvarint(65536)
			e.PutFixed(make([]byte, 64))
		}),
	}
	for name, in := range tests {
		if _, _, err := Decode(in); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: Decode = %v, want ErrInvalid", name, err)
		}
	}
}

func encodeRaw(typ Type, body func(e *enc)) []byte {
	var e enc
	e.PutFixed([]byte{Marker})
	e.PutUvarint(uint64(typ))
	e.PutUint64(1)
	body(&e)
	e.PutBytes(nil)
	return e.Bytes()
}

func TestEncodeRejects(t *testing.T) {
	many := make([]Node, MaxNodes+1)
	for i := range many {
		many[i] = Node{Addr: v4}
	}
	tests := map[string]Message{
		"zero address":   &PingReply{Flags: flag},
		"port zero":      &PingReply{Observed: netip.AddrPortFrom(v4.Addr(), 0), Flags: flag},
		"flags":          &Ping{Flags: 0x10},
		"status":         &PunchReply{Status: maxStatus + 1},
		"class":          &PunchReply{Class: maxClass + 1},
		"too many nodes": &FindNodeReply{Observed: v4, Nodes: many},
		"node address":   &FindNodeReply{Observed: v4, Nodes: []Node{{}}},
	}
	for name, m := range tests {
		if _, err := Encode(1, m, 0); err == nil {
			t.Errorf("%s: Encode succeeded", name)
		}
	}
}

// TestIPv6Refused checks that v0.1.x is IPv4 only on the wire: no message encodes an IPv6 address, IPv4-mapped
// included, in any address field.
func TestIPv6Refused(t *testing.T) {
	v6 := netip.MustParseAddrPort("[2001:db8::77]:4321")
	node := func(a netip.AddrPort) []Node { return []Node{{NewFlags(1, true), v4}, {NewFlags(2, true), a}} }
	rec := func(a netip.AddrPort) []Record {
		return []Record{{Key: fill(9), Addr: v4, Sig: sig(8)}, {Key: fill(10), Addr: a, Sig: sig(7)}}
	}
	tests := map[string]func(a netip.AddrPort) Message{
		"PING reply observed":      func(a netip.AddrPort) Message { return &PingReply{Observed: a, Flags: flag} },
		"FIND_NODE reply observed": func(a netip.AddrPort) Message { return &FindNodeReply{Observed: a, Flags: flag} },
		"FIND_NODE reply node":     func(a netip.AddrPort) Message { return &FindNodeReply{Observed: v4, Flags: flag, Nodes: node(a)} },
		"LOOKUP reply observed":    func(a netip.AddrPort) Message { return &LookupReply{Observed: a, Flags: flag} },
		"LOOKUP reply node":        func(a netip.AddrPort) Message { return &LookupReply{Observed: v4, Flags: flag, Nodes: node(a)} },
		"LOOKUP reply record":      func(a netip.AddrPort) Message { return &LookupReply{Observed: v4, Flags: flag, Records: rec(a)} },
		"ANNOUNCE address":         func(a netip.AddrPort) Message { return &Announce{Flags: flag, Addr: a} },
		"ANNOUNCE reply observed":  func(a netip.AddrPort) Message { return &AnnounceReply{Observed: a} },
		"CONNECT reply observed":   func(a netip.AddrPort) Message { return &ConnectReply{Observed: a} },
		"PUNCH requester address":  func(a netip.AddrPort) Message { return &Punch{Flags: flag, Addr: a} },
	}
	for name, mk := range tests {
		for _, a := range []netip.AddrPort{v6, netip.MustParseAddrPort("[fe80::1%eth0]:4000"), netip.MustParseAddrPort("[64:ff9b::cb00:7107]:4000"), netip.MustParseAddrPort("[::ffff:203.0.113.7]:4000")} {
			if _, err := Encode(1, mk(a), 0); !errors.Is(err, ErrInvalid) {
				t.Errorf("%s: Encode with %s: %v, want ErrInvalid", name, a, err)
			}
		}
	}
}

func TestFit(t *testing.T) {
	nodes := make([]Node, MaxNodes)
	for i := range nodes {
		nodes[i] = Node{Flags: NewFlags(uint8(i%8), true), Addr: v4b}
	}
	recs := make([]Record, MaxRecords)
	for i := range recs {
		recs[i] = Record{Key: fill(byte(i)), Addr: v4b, Age: 1, Sig: sig(1)}
	}
	m := &LookupReply{Observed: v4b, Token: fill(1), Flags: flag, Nodes: nodes, Records: recs}
	if _, err := Encode(1, m, MaxSize); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("full reply fits in %d bytes, test needs a larger one", MaxSize)
	}
	for _, size := range []int{MaxSize, 600, 300, 100} {
		b, err := Fit(1, m, size)
		if err != nil {
			t.Fatalf("Fit(%d): %v", size, err)
		}
		if len(b) > size {
			t.Fatalf("Fit(%d) gave %d bytes", size, len(b))
		}
		_, got, err := Decode(b)
		if err != nil {
			t.Fatalf("Fit(%d) output does not decode: %v", size, err)
		}
		r := got.(*LookupReply)
		if len(r.Records) > 0 && len(r.Nodes) < MaxNodes {
			t.Fatalf("Fit(%d) dropped nodes before records", size)
		}
	}
	if len(m.Nodes) != MaxNodes || len(m.Records) != MaxRecords {
		t.Fatal("Fit modified its argument")
	}
	if _, err := Fit(1, m, 20); !errors.Is(err, ErrTooLarge) {
		t.Errorf("Fit below the fixed fields: %v, want ErrTooLarge", err)
	}
	b, err := Fit(1, &FindNodeReply{Observed: v4b, Nodes: nodes}, 200)
	if err != nil || len(b) > 200 {
		t.Fatalf("Fit FindNodeReply: %d bytes, %v", len(b), err)
	}
}

func TestFlags(t *testing.T) {
	for r := range uint8(8) {
		for _, s := range []bool{false, true} {
			f := NewFlags(r, s)
			if f.R() != r || f.Server() != s {
				t.Errorf("NewFlags(%d, %v) = %#x: R %d Server %v", r, s, f, f.R(), f.Server())
			}
		}
	}
	if NewFlags(9, false).R() != 1 {
		t.Error("NewFlags does not keep the low 3 bits of r")
	}
}

func TestPeek(t *testing.T) {
	for _, m := range samples() {
		b, err := Encode(99, m, 0)
		if err != nil {
			t.Fatal(err)
		}
		typ, id, ok := Peek(b)
		if !ok || typ != m.Type() || id != 99 {
			t.Fatalf("Peek(%T) = %d %d %v", m, typ, id, ok)
		}
	}
	for _, in := range [][]byte{{}, {Marker}, {0x40, 1, 0, 0, 0, 0, 0, 0, 0, 0}, {Marker, 1, 0}, {Marker, 0x80, 0x00, 0, 0, 0, 0, 0, 0, 0, 0}} {
		if _, _, ok := Peek(in); ok {
			t.Errorf("Peek(%x) accepted", in)
		}
	}
}
