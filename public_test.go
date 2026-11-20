package kolodht

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/ciranda-dev/kolo-dht/internal/addrs"
)

// useServers replaces the built-in list for one test, so no test sends a packet to a real public address.
func useServers(t *testing.T, list []netip.AddrPort) {
	t.Helper()
	old := publicServers
	publicServers = list
	t.Cleanup(func() { publicServers = old })
}

func TestPublicServersData(t *testing.T) {
	list := PublicServers()
	if len(list) == 0 || len(list) > maxBoot {
		t.Fatalf("%d public servers, want 1 to %d", len(list), maxBoot)
	}
	seen := map[netip.AddrPort]bool{}
	for _, s := range list {
		switch {
		case !addrs.IPv4(s):
			t.Errorf("%v is not IPv4", s)
		case addrs.ScopeOf(s.Addr()) != addrs.Global:
			t.Errorf("%v is not a global address", s)
		case s.Port() == 0:
			t.Errorf("%v has no port", s)
		case seen[s]:
			t.Errorf("%v is listed twice", s)
		}
		seen[s] = true
	}
}

func TestPublicServersIsACopy(t *testing.T) {
	a := PublicServers()
	a[0] = netip.MustParseAddrPort("127.0.0.1:1")
	if PublicServers()[0] == a[0] {
		t.Fatal("changing the returned list changed the built-in one")
	}
}

// Bootstrap treats any nil slice as the public network, also a variable that was never appended to: this is by design
// and documented, so a change that makes nil an error or private must change this test and the docs.
func TestBootstrapNilUsesPublicServers(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t, 10*time.Second)
	server := loopNode(t, fastConfig(true))
	useServers(t, []netip.AddrPort{addrOf(server)})
	n := loopNode(t, fastConfig(false))
	var configured []netip.AddrPort
	if err := n.Bootstrap(ctx, configured); err != nil {
		t.Fatalf("Bootstrap with the built-in list: %v", err)
	}
	n.mu.Lock()
	held := n.table.Len()
	n.mu.Unlock()
	if held != 1 {
		t.Fatalf("table holds %d nodes, want the one built-in server", held)
	}
}

func TestBootstrapEmptyListSkipsPublicServers(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t, 10*time.Second)
	watch := newRaw(t)
	useServers(t, []netip.AddrPort{watch.addr()})
	n := loopNode(t, fastConfig(false))
	if err := n.Bootstrap(ctx, []netip.AddrPort{}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("empty list: %v", err)
	}
	watch.pc.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	if _, _, err := watch.pc.ReadFromUDPAddrPort(make([]byte, 2048)); err == nil {
		t.Fatal("an explicit empty list still sent a packet to the built-in server")
	}
}

func TestBootstrapNilWithSilentPublicServers(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t, 10*time.Second)
	useServers(t, []netip.AddrPort{newRaw(t).addr()})
	n := loopNode(t, fastConfig(false))
	if err := n.Bootstrap(ctx, nil); !errors.Is(err, ErrNoNodes) {
		t.Fatalf("silent built-in server: %v", err)
	}
}
