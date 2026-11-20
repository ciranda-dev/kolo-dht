package kolodht

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"github.com/ciranda-dev/kolo-dht/internal/netsim"
	"github.com/ciranda-dev/kolo-dht/internal/table"
	"github.com/ciranda-dev/kolo-dht/internal/wire"
)

// dropConn is a server socket that loses the requests drop matches.
type dropConn struct {
	*netsim.Conn
	drop func(wire.Message) bool
}

func (c dropConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		k, from, err := c.Conn.ReadFrom(b)
		if err != nil {
			return k, from, err
		}
		if _, m, err := wire.Decode(b[:k]); err != nil || !c.drop(m) {
			return k, from, nil
		}
	}
}

// dropping starts a public server that loses every request of type T.
func dropping[T wire.Message](s *sim) *Node {
	s.t.Helper()
	s.servers++
	h, err := s.net.AddHost(s.ip(18 + byte(1-s.servers%2)))
	if err != nil {
		s.t.Fatal(err)
	}
	pc, err := h.ListenUDP(4000)
	if err != nil {
		s.t.Fatal(err)
	}
	drop := func(m wire.Message) bool { _, ok := m.(T); return ok }
	listen := func() (net.PacketConn, error) { return h.ListenUDP(0) }
	tm := simTiming
	tm.randomPort = aim(s.net, h)
	n, err := newConn(context.Background(), dropConn{pc, drop}, listen, ident(s.t), fastConfig(true), tm, s.next)
	if err != nil {
		s.t.Fatal(err)
	}
	s.t.Cleanup(func() { n.Close() })
	return n
}

// fails is the failure count of server in n's table.
func fails(t *testing.T, n *Node, server netip.AddrPort) int {
	t.Helper()
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, e := range n.table.Closest(table.ID{}, n.table.Len()) {
		if e.Addr == server {
			return e.Fails
		}
	}
	t.Fatalf("%v is not in the table", server)
	return 0
}

// TestDeadlineCutsRequests runs each call against a server that answers every step but one, with a deadline that
// passes while that step's request waits and a context whose Err stays nil: the call must report the deadline.
func TestDeadlineCutsRequests(t *testing.T) {
	late := func() lateTimer { return lateTimer{context.Background(), time.Now().Add(100 * time.Millisecond)} }
	t.Run("Announce, STORE cut", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s := newSim(t, netsim.Config{})
			srv := dropping[*wire.Announce](s)
			n := s.peer(natKinds[0], fastConfig(false))
			if err := n.Bootstrap(testCtx(t, 10*time.Second), []netip.AddrPort{addrOf(srv)}); err != nil {
				t.Fatal(err)
			}
			if err := n.Announce(late(), topicOf("cut")); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("Announce: %v", err)
			}
		})
	})
	t.Run("Bootstrap, final lookup cut", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s := newSim(t, netsim.Config{})
			srv := dropping[*wire.FindNode](s)
			n := s.peer(natKinds[0], fastConfig(false))
			if err := n.Bootstrap(late(), []netip.AddrPort{addrOf(srv)}); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("Bootstrap: %v", err)
			}
		})
	})
	t.Run("Lookup, server not marked failed", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx := testCtx(t, 10*time.Second)
			s := newSim(t, netsim.Config{})
			srv := dropping[*wire.Lookup](s)
			n := s.peer(natKinds[0], fastConfig(false))
			if err := n.Bootstrap(ctx, []netip.AddrPort{addrOf(srv)}); err != nil {
				t.Fatal(err)
			}
			if _, err := n.Lookup(late(), topicOf("cut")); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("Lookup: %v", err)
			}
			if f := fails(t, n, addrOf(srv)); f != 0 {
				t.Fatalf("%d failures counted for a request the deadline cut", f)
			}
			// The same timeout before the deadline is a failure.
			if _, err := n.Lookup(ctx, topicOf("cut")); !errors.Is(err, ErrNoNodes) {
				t.Fatalf("Lookup: %v", err)
			}
			if f := fails(t, n, addrOf(srv)); f != 1 {
				t.Fatalf("%d failures counted for a timeout, want 1", f)
			}
		})
	})
}

func TestBootstrapClosedDuringLookup(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		s := newSim(t, netsim.Config{})
		srv := dropping[*wire.FindNode](s)
		n := s.peer(natKinds[0], fastConfig(false))
		errc := make(chan error, 1)
		go func() { errc <- n.Bootstrap(testCtx(t, 10*time.Second), []netip.AddrPort{addrOf(srv)}) }()
		synctest.Wait() // the ping was answered and the lookup waits for its FIND_NODE
		if err := n.Close(); err != nil {
			t.Fatal(err)
		}
		if err := <-errc; !errors.Is(err, ErrClosed) {
			t.Fatalf("Bootstrap closed during its lookup: %v", err)
		}
	})
}
