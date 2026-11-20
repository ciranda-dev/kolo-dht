package kolodht

import (
	"context"
	"math/big"
	"net/netip"
	"testing"
	"time"

	"github.com/ciranda-dev/kolo-dht/internal/netsim"
	"github.com/ciranda-dev/kolo-dht/internal/wire"
)

// FuzzHandlePacket feeds arbitrary datagrams to a server node's handler: it must never panic or reply larger.
func FuzzHandlePacket(f *testing.F) {
	net := netsim.New(netsim.Config{})
	h, err := net.AddHost(netip.MustParseAddr("203.0.113.1"))
	if err != nil {
		f.Fatal(err)
	}
	pc, err := h.ListenUDP(4000)
	if err != nil {
		f.Fatal(err)
	}
	cfg := fastConfig(true)
	cfg.MaxRequestsPerIP, cfg.MaxRequestsPerPrefix, cfg.MaxRequests = 10_000, 100_000, 1_000_000
	n, err := newConn(context.Background(), pc, nil, ident(f), cfg, simTiming, 1)
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { n.Close() })
	ph, err := net.AddHost(netip.MustParseAddr("198.51.100.1"))
	if err != nil {
		f.Fatal(err)
	}
	peer, err := ph.ListenUDP(5000)
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { peer.Close() })
	from := peer.Addr()

	tok := [32]byte{1}
	srv := wire.NewFlags(2, true)
	seeds := []wire.Message{
		&wire.Ping{}, &wire.FindNode{}, &wire.Lookup{}, &wire.Announce{Token: tok, Addr: from},
		&wire.Ping{Flags: srv}, &wire.FindNode{Flags: srv}, &wire.Lookup{Flags: srv},
		&wire.Connect{Token: tok}, &wire.Punch{Addr: from}, &wire.Probe{}, &wire.Probe{Nonce: [8]byte{1}},
		&wire.PingReply{Observed: from}, &wire.LookupReply{Observed: from},
	}
	for _, m := range seeds {
		for _, size := range []int{0, wire.MaxSize} {
			if b, err := wire.Encode(1, m, size); err == nil {
				f.Add(b)
			}
		}
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		n.handlePacket(in, from, time.Now())
		// Everything the node sends to the source in answer, check pings included, goes out before handlePacket returns.
		total := 0
		buf := make([]byte, 2048)
		for {
			peer.SetReadDeadline(time.Now().Add(time.Millisecond))
			k, _, err := peer.ReadFrom(buf)
			if err != nil {
				break
			}
			total += k
		}
		if total > len(in) {
			t.Fatalf("%d bytes sent for a datagram of %d", total, len(in))
		}
	})
}

// FuzzCloser checks Closer against comparing both Distance values as big-endian unsigned integers.
func FuzzCloser(f *testing.F) {
	f.Add([]byte{}, []byte{1}, []byte{2})
	f.Add([]byte{0x80}, []byte{0x7f, 0xff}, []byte{0x80, 0})
	f.Add([]byte{5}, []byte{9}, []byte{9})
	f.Fuzz(func(t *testing.T, tb, ab, bb []byte) {
		var target, a, b [32]byte
		copy(target[:], tb)
		copy(a[:], ab)
		copy(b[:], bb)
		da, db := Distance(a, target), Distance(b, target)
		want := new(big.Int).SetBytes(da[:]).Cmp(new(big.Int).SetBytes(db[:])) < 0
		if got := Closer(target, a, b); got != want {
			t.Fatalf("Closer(%x, %x, %x) = %v, want %v", target, a, b, got, want)
		}
		if Distance(a, b) != Distance(b, a) || Distance(a, a) != ([32]byte{}) {
			t.Fatalf("Distance of %x and %x is not symmetric or not zero to self", a, b)
		}
	})
}
