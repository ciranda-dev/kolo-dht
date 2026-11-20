package kolodht

// Tests in this file run whole nodes (kolo-dht, kolo-secure, kolo-transport and quic-go) over internal/netsim. NAT
// results are proven only in that simulation. Hosts use 198.18.0.0/15 and never reach a real network.

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/ciranda-dev/kolo-dht/internal/netsim"
	"github.com/ciranda-dev/kolo-dht/internal/punch"
	"github.com/ciranda-dev/kolo-dht/internal/records"
	"github.com/ciranda-dev/kolo-dht/internal/wire"
)

var simTiming = timing{
	refresh:   300 * time.Millisecond,
	ttl:       2 * time.Second,
	relookup:  3 * time.Second,
	maintain:  time.Second,
	rChange:   time.Second,
	sampleAge: time.Minute,

	consistentEvery: 20 * time.Millisecond,
	randomEvery:     time.Millisecond,
	keepAliveDelay:  5 * time.Millisecond,
	randomPort:      randomPort,
}

type sim struct {
	t       *testing.T
	net     *netsim.Network
	next    int
	servers int
	odds    bool // probes go to random ports, with the real odds of a birthday punch
}

func newSim(t *testing.T, cfg netsim.Config) *sim {
	return &sim{t: t, net: netsim.New(cfg)}
}

func (s *sim) ip(prefix byte) netip.Addr {
	s.next++
	return netip.AddrFrom4([4]byte{198, prefix, byte(s.next), 1})
}

// aim is a probe port source that cycles through the mappings the peer's NAT keeps open toward h, so a birthday punch
// connects without luck; while there is none it gives MinRandomPort, which no NAT maps.
func aim(net *netsim.Network, h *netsim.Host) func(netip.Addr) uint16 {
	var i atomic.Uint32
	return func(ip netip.Addr) uint16 {
		ports := net.Ports(ip, h)
		if len(ports) == 0 {
			return punch.MinRandomPort
		}
		return ports[int(i.Add(1)-1)%len(ports)]
	}
}

func (s *sim) start(pc *netsim.Conn, cfg *Config, r int) *Node {
	s.t.Helper()
	listen := func() (net.PacketConn, error) { return pc.Host().ListenUDP(0) }
	tm := simTiming
	if !s.odds {
		tm.randomPort = aim(s.net, pc.Host())
	}
	n, err := newConn(context.Background(), pc, listen, ident(s.t), cfg, tm, r)
	if err != nil {
		s.t.Fatal(err)
	}
	s.t.Cleanup(func() { n.Close() })
	return n
}

// server starts a public server in its own /24, in 198.18.0.0/16 and 198.19.0.0/16 in turn, so the servers of a
// lookup are in two networks.
func (s *sim) server() *Node {
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
	return s.start(pc, fastConfig(true), s.next)
}

// natKind is one row or column of the hole punching table in docs/protocol.md.
type natKind struct {
	name   string
	public bool
	cfg    netsim.NATConfig
}

var natKinds = []natKind{
	{"public", true, netsim.NATConfig{}},
	{"full-cone", false, netsim.NATConfig{Mapping: netsim.EndpointIndependent, Filtering: netsim.EndpointIndependentFiltering}},
	{"restricted", false, netsim.NATConfig{Mapping: netsim.EndpointIndependent, Filtering: netsim.AddressDependentFiltering}},
	{"port-restricted", false, netsim.NATConfig{Mapping: netsim.EndpointIndependent, Filtering: netsim.AddressPortDependentFiltering}},
	{"symmetric", false, netsim.NATConfig{Mapping: netsim.AddressPortDependent, Filtering: netsim.AddressPortDependentFiltering}},
	{"address-dependent", false, netsim.NATConfig{Mapping: netsim.AddressDependent, Filtering: netsim.AddressDependentFiltering}},
}

// peer starts a client: public, or alone behind a new NAT of the given kind.
func (s *sim) peer(k natKind, cfg *Config) *Node {
	s.t.Helper()
	var h *netsim.Host
	var err error
	if k.public {
		h, err = s.net.AddHost(s.ip(19))
	} else {
		var nat *netsim.NAT
		nat, err = s.net.AddNAT(s.ip(19), k.cfg)
		if err == nil {
			h, err = nat.AddHost(netip.MustParseAddr("10.0.0.2"))
		}
	}
	if err != nil {
		s.t.Fatal(err)
	}
	pc, err := h.ListenUDP(5000)
	if err != nil {
		s.t.Fatal(err)
	}
	return s.start(pc, cfg, -1)
}

func bootstrap(t *testing.T, ctx context.Context, servers []*Node, nodes ...*Node) {
	t.Helper()
	var addrs []netip.AddrPort
	for _, s := range servers {
		addrs = append(addrs, addrOf(s))
	}
	for _, n := range nodes {
		if err := n.Bootstrap(ctx, addrs); err != nil {
			t.Fatal(err)
		}
	}
}

// isRandom reports whether k maps each destination to another port.
func isRandom(k natKind) bool { return !k.public && k.cfg.Mapping != netsim.EndpointIndependent }

// punchWorks is the expected outcome: every pair connects unless both mappings are random; a random side punches
// with birthday sockets against the other side's random-port probes.
func punchWorks(a, b string) bool {
	random := func(k string) bool { return k == "symmetric" || k == "address-dependent" }
	return !random(a) || !random(b)
}

// connectPair announces b, looks it up from a and connects; it returns Connect's error and checks both ends on success.
func connectPair(t *testing.T, ctx context.Context, a, b *Node, topic Topic) error {
	t.Helper()
	if err := b.Announce(ctx, topic); err != nil {
		t.Fatalf("Announce: %v", err)
	}
	recs, err := a.Lookup(ctx, topic)
	if err != nil || len(recs) != 1 || !bytes.Equal(recs[0].PublicKey, b.id.PublicKey()) {
		t.Fatalf("Lookup = %+v, %v", recs, err)
	}
	ca, err := a.Connect(ctx, recs[0])
	if err != nil {
		return err
	}
	defer ca.Close()
	if !bytes.Equal(ca.RemotePublicKey(), b.id.PublicKey()) {
		t.Fatal("Connect reached another key")
	}
	actx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cb, err := b.Accept(actx)
	if err != nil {
		t.Fatalf("announcer Accept: %v", err)
	}
	defer cb.Close()
	if !bytes.Equal(cb.RemotePublicKey(), a.id.PublicKey()) {
		t.Fatal("announcer accepted another key")
	}
	echo(t, ctx, ca, cb)
	return nil
}

// TestSimPunchMatrix checks the NAT table with three servers, the fewest that classify a mapping.
func TestSimPunchMatrix(t *testing.T) {
	checkGoroutines(t)
	// One expected miss happens about once in 60 runs; more than one retry in a run means punching got worse.
	var retries atomic.Int32
	t.Cleanup(func() {
		if n := retries.Load(); n > 1 {
			t.Errorf("%d birthday punches needed a retry in one run, want at most 1", n)
		}
	})
	for _, ka := range natKinds {
		for _, kb := range natKinds {
			t.Run(ka.name+"/"+kb.name, func(t *testing.T) {
				t.Parallel()
				synctest.Test(t, func(t *testing.T) {
					ctx := testCtx(t, 30*time.Second)
					s := newSim(t, netsim.Config{Seed: 1})
					s.odds = true
					servers := []*Node{s.server(), s.server(), s.server()}
					bootstrap(t, ctx, servers[1:], servers[0])
					cfg := func() *Config {
						c := fastConfig(false)
						c.RandomPunchInterval, c.RandomPunchCooldown = time.Second, time.Second
						return c
					}
					a, b := s.peer(ka, cfg()), s.peer(kb, cfg())
					bootstrap(t, ctx, servers, a, b)
					start := time.Now()
					err := connectPair(t, ctx, a, b, topicOf("matrix"))
					want := punchWorks(ka.name, kb.name)
					// A birthday punch misses about 1 time in 1000, so a failed one gets one retry after its doubled
					// cooldown, as kolo-swarm retries; two misses in a row mean the punch is broken.
					if want && errors.Is(err, ErrUnreachable) && (isRandom(ka) || isRandom(kb)) {
						retries.Add(1)
						t.Logf("birthday punch missed once: %v", err)
						time.Sleep(2*time.Second + 100*time.Millisecond)
						err = connectPair(t, ctx, a, b, topicOf("matrix"))
					}
					switch {
					case want && err != nil:
						t.Fatalf("Connect %s to %s: %v, want success", ka.name, kb.name, err)
					case !want && !errors.Is(err, ErrUnreachable):
						t.Fatalf("Connect %s to %s: %v, want ErrUnreachable", ka.name, kb.name, err)
					}
					// Two random mappings are known in advance: Connect gives up at once, without punching.
					if !want && ka.cfg.Mapping != netsim.EndpointIndependent && kb.cfg.Mapping != netsim.EndpointIndependent && !ka.public && !kb.public {
						if d := time.Since(start); d > time.Second {
							t.Fatalf("both random: Connect took %v", d)
						}
					}
				})
			})
		}
	}
}

// TestSimClass classifies each NAT kind from three servers, the fewest that classify.
func TestSimClass(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		ctx := testCtx(t, 10*time.Second)
		s := newSim(t, netsim.Config{Seed: 2})
		servers := []*Node{s.server(), s.server(), s.server()}
		for _, k := range natKinds {
			n := s.peer(k, fastConfig(false))
			bootstrap(t, ctx, servers, n)
			n.mu.Lock()
			got := n.nat.class(time.Now())
			n.mu.Unlock()
			want := wire.ClassConsistent
			if !k.public && k.cfg.Mapping != netsim.EndpointIndependent {
				want = wire.ClassRandom
			}
			if got != want {
				t.Errorf("%s: class %v, want %v", k.name, got, want)
			}
		}
	})
}

// TestSimRefreshKeepsMapping shows that refreshes keep the announcer reachable through a NAT whose mappings expire, and
// that without them the relay cannot reach it.
func TestSimRefreshKeepsMapping(t *testing.T) {
	checkGoroutines(t)
	for _, refresh := range []bool{true, false} {
		t.Run(map[bool]string{true: "refresh", false: "none"}[refresh], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx := testCtx(t, 30*time.Second)
				s := newSim(t, netsim.Config{Seed: 3})
				srv := s.server()
				k := natKinds[3] // port-restricted
				k.cfg.Timeout = time.Second
				a, b := s.peer(natKinds[0], fastConfig(false)), s.peer(k, fastConfig(false))
				if !refresh {
					b.tm.refresh, b.tm.relookup = time.Hour, time.Hour
					srv.mu.Lock()
					srv.store = newStoreTTL(srv, time.Hour)
					srv.mu.Unlock()
				}
				bootstrap(t, ctx, []*Node{srv}, a, b)
				topic := topicOf("refresh")
				if err := b.Announce(ctx, topic); err != nil {
					t.Fatal(err)
				}
				time.Sleep(2500 * time.Millisecond)
				recs, err := a.Lookup(ctx, topic)
				if err != nil || len(recs) != 1 {
					t.Fatalf("Lookup = %d records, %v", len(recs), err)
				}
				c, err := a.Connect(ctx, recs[0])
				if refresh && err != nil {
					t.Fatalf("Connect with refreshes: %v", err)
				}
				if !refresh && !errors.Is(err, ErrUnreachable) {
					t.Fatalf("Connect after the mapping expired: %v, want ErrUnreachable", err)
				}
				if c != nil {
					c.Close()
				}
			})
		})
	}
}

// TestSimSameNAT connects two peers behind one NAT, which works only if it hairpins.
func TestSimSameNAT(t *testing.T) {
	checkGoroutines(t)
	for _, hairpin := range []bool{true, false} {
		t.Run(map[bool]string{true: "hairpin", false: "no-hairpin"}[hairpin], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx := testCtx(t, 30*time.Second)
				s := newSim(t, netsim.Config{Seed: 4})
				servers := []*Node{s.server(), s.server()}
				nat, err := s.net.AddNAT(s.ip(19), netsim.NATConfig{Filtering: netsim.AddressPortDependentFiltering, Hairpin: hairpin})
				if err != nil {
					t.Fatal(err)
				}
				var peers []*Node
				for _, ip := range []string{"10.0.0.2", "10.0.0.3"} {
					h, err := nat.AddHost(netip.MustParseAddr(ip))
					if err != nil {
						t.Fatal(err)
					}
					pc, err := h.ListenUDP(5000)
					if err != nil {
						t.Fatal(err)
					}
					peers = append(peers, s.start(pc, fastConfig(false), -1))
				}
				bootstrap(t, ctx, servers, peers...)
				err = connectPair(t, ctx, peers[0], peers[1], topicOf("same-nat"))
				if hairpin && err != nil {
					t.Fatalf("with hairpinning: %v", err)
				}
				if !hairpin && !errors.Is(err, ErrUnreachable) {
					t.Fatalf("without hairpinning: %v, want ErrUnreachable", err)
				}
			})
		})
	}
}

// TestSimConnectFailover closes the freshest relay; Connect goes on to the next one.
func TestSimConnectFailover(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		ctx := testCtx(t, 30*time.Second)
		s := newSim(t, netsim.Config{Seed: 5})
		servers := []*Node{s.server(), s.server(), s.server()}
		bootstrap(t, ctx, servers[1:], servers[0])
		a, b := s.peer(natKinds[3], fastConfig(false)), s.peer(natKinds[3], fastConfig(false))
		bootstrap(t, ctx, servers, a, b)
		topic := topicOf("failover")
		if err := b.Announce(ctx, topic); err != nil {
			t.Fatal(err)
		}
		recs, err := a.Lookup(ctx, topic)
		if err != nil || len(recs) != 1 || len(recs[0].relays) < 2 {
			t.Fatalf("Lookup = %+v, %v", recs, err)
		}
		first := recs[0].relays[0].server
		for _, srv := range servers {
			if addrOf(srv) == first {
				srv.Close()
			}
		}
		c, err := a.Connect(ctx, recs[0])
		if err != nil {
			t.Fatalf("Connect with the first relay down: %v", err)
		}
		c.Close()
	})
}

// TestSimLookupClosest stores a record in a network of 30 servers in distinct /24s and checks it lands at
// the servers closest to the topic and is found from another server's side of the network.
func TestSimLookupClosest(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		ctx := testCtx(t, 60*time.Second)
		s := newSim(t, netsim.Config{Seed: 6})
		var servers []*Node
		for range 30 {
			servers = append(servers, s.server())
		}
		bootstrap(t, ctx, servers[:1], servers[1:]...)
		bootstrap(t, ctx, servers[len(servers)-1:], servers[0])
		a, b := s.peer(natKinds[1], fastConfig(false)), s.peer(natKinds[1], fastConfig(false))
		bootstrap(t, ctx, servers[:1], b)
		bootstrap(t, ctx, servers[len(servers)-1:], a)
		topic := topicOf("closest")
		if err := b.Announce(ctx, topic); err != nil {
			t.Fatal(err)
		}
		holding := 0
		for _, srv := range servers {
			srv.mu.Lock()
			if srv.store.Len(time.Now()) == 1 {
				holding++
			}
			srv.mu.Unlock()
		}
		if holding < 15 {
			t.Fatalf("record stored at %d servers, want at least 15 of the 20 closest", holding)
		}
		recs, err := a.Lookup(ctx, topic)
		if err != nil || len(recs) != 1 || len(recs[0].relays) != maxRelays {
			t.Fatalf("Lookup = %+v, %v", recs, err)
		}
	})
}

func newStoreTTL(n *Node, ttl time.Duration) *records.Store {
	c := n.cfg
	return records.NewStore(records.Limits{Records: c.MaxRecords, PerTopic: c.MaxRecordsPerTopic, PerHost: c.MaxRecordsPerIP, PerGroup: perGroup(c.MaxRecordsPerTopic), TTL: ttl})
}

// TestSimIDCollision starts two servers on one IP with the same r: they must move apart and see each other.
func TestSimIDCollision(t *testing.T) {
	checkGoroutines(t)
	synctest.Test(t, func(t *testing.T) {
		ctx := testCtx(t, 10*time.Second)
		s := newSim(t, netsim.Config{Seed: 7})
		h, err := s.net.AddHost(netip.MustParseAddr("198.18.200.1"))
		if err != nil {
			t.Fatal(err)
		}
		var servers []*Node
		for _, port := range []uint16{4000, 4001} {
			pc, err := h.ListenUDP(port)
			if err != nil {
				t.Fatal(err)
			}
			servers = append(servers, s.start(pc, fastConfig(true), 3))
		}
		a, b := servers[0], servers[1]
		bootstrap(t, ctx, []*Node{b}, a)
		bootstrap(t, ctx, []*Node{a}, b)
		if a.r.Load() == b.r.Load() {
			t.Fatalf("both servers still use r %d", a.r.Load())
		}
		for _, n := range servers {
			n.mu.Lock()
			held := n.table.Len()
			n.mu.Unlock()
			if held != 1 {
				t.Fatalf("server table holds %d entries, want the other server", held)
			}
		}
	})
}
