package wire

import (
	"bytes"
	"testing"
)

func FuzzDecode(f *testing.F) {
	for _, m := range samples() {
		for _, size := range []int{0, 300, MaxSize} {
			if b, err := Encode(3, m, size); err == nil {
				f.Add(b)
			}
		}
	}
	f.Add([]byte{Marker, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{Marker, 0x80, 0x00})
	f.Fuzz(func(t *testing.T, in []byte) {
		typ, pid, pok := Peek(in)
		id, m, err := Decode(in)
		if err != nil {
			return
		}
		if !pok || typ != m.Type() || pid != id {
			t.Fatalf("Peek = %d %d %v, Decode = %d %d", typ, pid, pok, m.Type(), id)
		}
		if len(in) > MaxSize {
			t.Fatalf("decoded %d bytes", len(in))
		}
		out, err := Encode(id, m, len(in))
		if err != nil {
			t.Fatalf("decoded %x but Encode fails: %v", in, err)
		}
		if !bytes.Equal(out, in) {
			t.Fatalf("decoded %x but re-encodes to %x", in, out)
		}
	})
}

func FuzzFit(f *testing.F) {
	f.Add(uint8(20), uint8(16), uint16(MaxSize))
	f.Add(uint8(3), uint8(0), uint16(80))
	f.Fuzz(func(t *testing.T, n, r uint8, size uint16) {
		nodes := make([]Node, int(n)%(MaxNodes+1))
		for i := range nodes {
			nodes[i] = Node{Addr: v4b}
		}
		recs := make([]Record, int(r)%(MaxRecords+1))
		for i := range recs {
			recs[i] = Record{Addr: v4}
		}
		b, err := Fit(1, &LookupReply{Observed: v4b, Nodes: nodes, Records: recs}, int(size))
		if err != nil {
			return
		}
		if len(b) > int(size) || len(b) > MaxSize {
			t.Fatalf("Fit(%d) gave %d bytes", size, len(b))
		}
		if _, _, err := Decode(b); err != nil {
			t.Fatalf("Fit output does not decode: %v", err)
		}
	})
}
