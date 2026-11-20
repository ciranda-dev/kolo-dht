package kolodht

import (
	"net/netip"
	"testing"
	"time"

	"github.com/ciranda-dev/kolo-dht/internal/ratelimit"
	"github.com/ciranda-dev/kolo-dht/internal/records"
	"github.com/ciranda-dev/kolo-dht/internal/wire"
)

// signedAnnounce is a valid ANNOUNCE for a new record from 127.0.0.1:port, with a token of s for that address.
func signedAnnounce(t *testing.T, s *Node, port uint16, now time.Time) (*wire.Announce, netip.AddrPort) {
	t.Helper()
	from := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)
	rec, err := records.Sign(ident(t), topicOf("budget"), from)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	tok := s.tokens.Make(from, now)
	s.mu.Unlock()
	return &wire.Announce{Token: tok, Topic: rec.Topic, Key: rec.Key, Addr: from, Sig: rec.Sig, Share: share(t)}, from
}

// A host that makes a server do more key agreements and signature checks than the budget in one window gets no
// reply for the rest of it, and is served again in the next window.
func TestAnnounceVerifyBudget(t *testing.T) {
	checkGoroutines(t)
	s := loopNode(t, fastConfig(true))
	now := time.Now()
	var ok, dropped int
	for i := range maxVerifiesPerIP + 10 {
		m, from := signedAnnounce(t, s, uint16(5000+i), now)
		out := s.storeAnnounce(m, from, now)
		switch {
		case out == nil:
			dropped++
		case out.Status == wire.StatusOK:
			ok++
		default:
			t.Fatalf("announce %d: status %v", i, out.Status)
		}
	}
	if ok != maxVerifiesPerIP || dropped != 10 {
		t.Fatalf("stored %d and dropped %d, want %d and 10", ok, dropped, maxVerifiesPerIP)
	}
	if got := s.Stats().Limited; got != 10 {
		t.Fatalf("Limited = %d, want 10", got)
	}
	later := now.Add(ratelimit.Window)
	m, from := signedAnnounce(t, s, 6000, later)
	if out := s.storeAnnounce(m, from, later); out == nil || out.Status != wire.StatusOK {
		t.Fatalf("announce in the next window: %+v", out)
	}
}

// A bad signature with a valid token costs the same budget as a real record, and is refused while the budget lasts.
func TestAnnounceVerifyBudgetBogus(t *testing.T) {
	checkGoroutines(t)
	s := loopNode(t, fastConfig(true))
	now := time.Now()
	var refused, dropped int
	for i := range maxVerifiesPerIP + 5 {
		m, from := signedAnnounce(t, s, uint16(5000+i), now)
		m.Sig[0] ^= 1
		out := s.storeAnnounce(m, from, now)
		switch {
		case out == nil:
			dropped++
		case out.Status == wire.StatusRefused:
			refused++
		default:
			t.Fatalf("bogus announce %d: %v", i, out.Status)
		}
	}
	if refused != maxVerifiesPerIP || dropped != 5 {
		t.Fatalf("refused %d and dropped %d, want %d and 5", refused, dropped, maxVerifiesPerIP)
	}
}

// A refresh of a stored record, same address, signature and share, costs no check: any number fit in one window.
// A refresh with a new share costs a key agreement and is counted.
func TestAnnounceRefreshNotCounted(t *testing.T) {
	checkGoroutines(t)
	s := loopNode(t, fastConfig(true))
	now := time.Now()
	m, from := signedAnnounce(t, s, 5000, now)
	if out := s.storeAnnounce(m, from, now); out == nil || out.Status != wire.StatusOK {
		t.Fatalf("first announce: %+v", out)
	}
	for i := range 5 * maxVerifiesPerIP {
		if out := s.storeAnnounce(m, from, now); out == nil || out.Status != wire.StatusOK {
			t.Fatalf("refresh %d: %+v", i, out)
		}
	}
	for i := range maxVerifiesPerIP - 1 {
		m2 := *m
		m2.Share = share(t)
		if out := s.storeAnnounce(&m2, from, now); out == nil || out.Status != wire.StatusOK {
			t.Fatalf("new share %d: %+v", i, out)
		}
	}
	m2 := *m
	m2.Share = share(t)
	if out := s.storeAnnounce(&m2, from, now); out != nil {
		t.Fatalf("a refresh with a new share past the budget got %+v", out)
	}
}
