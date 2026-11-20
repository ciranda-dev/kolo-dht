package kolodht

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func lowID(last ...byte) (out [32]byte) {
	copy(out[32-len(last):], last)
	return out
}

func TestDistanceVectors(t *testing.T) {
	var ones [32]byte
	for i := range ones {
		ones[i] = 0xff
	}
	var seq, inv [32]byte
	for i := range seq {
		seq[i] = byte(i)
		inv[i] = ^byte(i)
	}
	cases := []struct{ a, b, want [32]byte }{
		{lowID(), lowID(), lowID()},
		{lowID(1), lowID(2), lowID(3)},
		{lowID(0x0f, 0xf0), lowID(0xff, 0xff), lowID(0xf0, 0x0f)},
		{ones, lowID(), ones},
		{seq, ones, inv},
	}
	for _, c := range cases {
		if got := Distance(c.a, c.b); got != c.want {
			t.Errorf("Distance(%x, %x) = %x, want %x", c.a, c.b, got, c.want)
		}
	}
}

func TestDistanceSymmetricAndZeroToSelf(t *testing.T) {
	for i := range 64 {
		a := sha256.Sum256([]byte{byte(i), 'a'})
		b := sha256.Sum256([]byte{byte(i), 'b'})
		if Distance(a, b) != Distance(b, a) {
			t.Fatalf("Distance(%x, %x) is not symmetric", a, b)
		}
		if Distance(a, a) != ([32]byte{}) {
			t.Fatalf("Distance(%x, itself) is not zero", a)
		}
		if a != b && Distance(a, b) == ([32]byte{}) {
			t.Fatalf("Distance(%x, %x) is zero", a, b)
		}
	}
}

func TestCloserVectors(t *testing.T) {
	var high [32]byte
	high[0] = 0x80
	cases := []struct {
		target, a, b [32]byte
		want         bool
	}{
		{lowID(), lowID(1), lowID(2), true},
		{lowID(), lowID(2), lowID(1), false},
		{lowID(), lowID(1), lowID(1), false},
		{lowID(3), lowID(2), lowID(0), true},
		{lowID(), lowID(0xff), lowID(1, 0), true},
		{lowID(), lowID(1, 0), lowID(0xff), false},
		{lowID(), lowID(0xff, 0xff), high, true},
		{high, lowID(), lowID(1), true},
		{high, high, lowID(), true},
		{high, lowID(), high, false},
	}
	for _, c := range cases {
		if got := Closer(c.target, c.a, c.b); got != c.want {
			t.Errorf("Closer(%x, %x, %x) = %v, want %v", c.target, c.a, c.b, got, c.want)
		}
	}
}

func TestCloserMatchesDistanceBytes(t *testing.T) {
	for i := range 256 {
		target := sha256.Sum256([]byte{byte(i), 't'})
		a := sha256.Sum256([]byte{byte(i), 'a'})
		b := sha256.Sum256([]byte{byte(i), 'b'})
		// Same high bytes as target, so the comparison reaches the low bytes.
		copy(a[:30], target[:30])
		copy(b[:29+i%2], target[:29+i%2])
		for _, p := range [][2][32]byte{{a, b}, {b, a}, {a, a}} {
			da, db := Distance(p[0], target), Distance(p[1], target)
			want := bytes.Compare(da[:], db[:]) < 0
			if got := Closer(target, p[0], p[1]); got != want {
				t.Fatalf("Closer(%x, %x, %x) = %v, want %v", target, p[0], p[1], got, want)
			}
		}
	}
}
