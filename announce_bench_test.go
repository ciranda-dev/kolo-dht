package kolodht

import (
	"context"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/ciranda-dev/kolo-dht/internal/ratelimit"
	"github.com/ciranda-dev/kolo-dht/internal/wire"
)

func benchServer(b *testing.B) *Node {
	b.Helper()
	n, err := New(context.Background(), "127.0.0.1:0", ident(b), fastConfig(true))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { n.Close() })
	return n
}

// bogusAnnounce is an ANNOUNCE from an address with a valid token, a random share and a random signature.
func bogusAnnounce(n *Node, i int, now time.Time) (*wire.Announce, netip.AddrPort) {
	from := netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 18, byte(i >> 8), byte(i)}), 40000)
	m := &wire.Announce{Topic: topicOf("flood"), Addr: from}
	m.Key[0], m.Key[1], m.Key[2] = 1, byte(i>>8), byte(i)
	m.Share[0], m.Share[1], m.Share[2] = 9, byte(i>>8), byte(i)
	m.Sig[0], m.Sig[1] = byte(i), 7
	n.mu.Lock()
	m.Token = n.tokens.Make(from, now)
	n.mu.Unlock()
	return m, from
}

// BenchmarkStoreAnnounceBogus is the cost of one unauthenticated ANNOUNCE with a valid token and a bad signature, with
// no verification budget.
func BenchmarkStoreAnnounceBogus(b *testing.B) {
	n := benchServer(b)
	now := time.Now()
	n.verifies = ratelimit.New(1<<30, 1<<30, 1<<30, now)
	m, from := bogusAnnounce(n, 1, now)
	for b.Loop() {
		n.storeAnnounce(m, from, now)
	}
}

// BenchmarkAnnounceFlood sends bogus ANNOUNCEs from many addresses at the rate limits and reports how many were
// checked (answered) and how long another goroutine waited for the node lock.
func BenchmarkAnnounceFlood(b *testing.B) {
	for range b.N {
		n := benchServer(b)
		now := time.Now()
		const packets = 40000
		type pkt struct {
			m    *wire.Announce
			from netip.AddrPort
		}
		all := make([]pkt, packets)
		for i := range all {
			all[i].m, all[i].from = bogusAnnounce(n, i%(1<<15), now)
		}
		var waits []time.Duration
		var mu sync.Mutex
		stop := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				t := time.Now()
				n.mu.Lock()
				w := time.Since(t)
				n.mu.Unlock()
				mu.Lock()
				waits = append(waits, w)
				mu.Unlock()
				time.Sleep(50 * time.Microsecond)
			}
		}()
		served := 0
		start := time.Now()
		for i := 0; time.Since(start) < time.Second; i++ {
			p := all[i%len(all)]
			n.mu.Lock()
			ok := n.limiter.Allow(p.from.Addr(), time.Now())
			n.mu.Unlock()
			if !ok {
				continue
			}
			if n.storeAnnounce(p.m, p.from, time.Now()) != nil {
				served++
			}
		}
		close(stop)
		wg.Wait()
		slices.Sort(waits)
		b.ReportMetric(float64(served), "checked/s")
		b.ReportMetric(float64(waits[len(waits)/2].Microseconds()), "wait-p50-us")
		b.ReportMetric(float64(waits[len(waits)*99/100].Microseconds()), "wait-p99-us")
		b.ReportMetric(float64(waits[len(waits)-1].Microseconds()), "wait-max-us")
	}
}
