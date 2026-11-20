package kolodht

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ciranda-dev/kolo-dht/internal/addrs"
	"github.com/ciranda-dev/kolo-dht/internal/punch"
	"github.com/ciranda-dev/kolo-dht/internal/ratelimit"
	"github.com/ciranda-dev/kolo-dht/internal/records"
	"github.com/ciranda-dev/kolo-dht/internal/table"
	"github.com/ciranda-dev/kolo-dht/internal/token"
	"github.com/ciranda-dev/kolo-dht/internal/wire"
	koloid "github.com/ciranda-dev/kolo-id"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

const (
	alpha       = 10
	maxQueries  = 100
	maxRelays   = 3
	maxChecks   = 10
	maxBoot     = 64
	staleChecks = 5
	// pingSize pads our pings so the reply and a check ping both fit in it; checkSize pads a check ping for its reply.
	pingSize  = 160
	checkSize = 80
	// Concurrent relays per requester host and per target at a server.
	maxRelaysPerHost   = 2
	maxRelaysPerTarget = 4
	// Concurrent punch sessions toward one destination host, at the announcer and at the connector.
	maxDestAttempts = 2
	// maxProbeReplies caps the answers to probes in one session.
	maxProbeReplies = 4
	// maxVerify caps the signature checks of one Lookup.
	maxVerify = 160
)

// timing holds the protocol intervals, which tests shorten, and the port source of random probes toward ip, which
// tests aim at the peer's mappings.
type timing struct {
	refresh, ttl, relookup, maintain, rChange, sampleAge time.Duration
	consistentEvery, randomEvery, keepAliveDelay         time.Duration
	randomPort                                           func(ip netip.Addr) uint16
}

func randomPort(netip.Addr) uint16 { return punch.RandomPort() }

var defaultTiming = timing{
	refresh:   15 * time.Second,
	ttl:       20 * time.Minute,
	relookup:  5 * time.Minute,
	maintain:  40 * time.Second,
	rChange:   time.Minute,
	sampleAge: 30 * time.Minute,

	consistentEvery: punch.ConsistentEvery,
	randomEvery:     punch.RandomEvery,
	keepAliveDelay:  punch.KeepAliveDelay,
	randomPort:      randomPort,
}

var (
	errTimeout     = errors.New("kolodht: request timeout")
	errUnusable    = errors.New("kolodht: unusable address")
	errRefused     = errors.New("kolodht: refused")
	errBothRand    = errors.New("kolodht: both mappings random")
	errBusy        = errors.New("kolodht: too many attempts to this peer")
	errPunched     = errors.New("kolodht: punch failed")
	errPeerBusy    = errors.New("kolodht: peer asks to try later")
	errUnconfirmed = errors.New("kolodht: peer IP not confirmed by two networks")
)

// Node is a DHT node with one UDP socket for its DHT datagrams and its kolo-secure connections.
type Node struct {
	id    *koloid.Identity
	key   [wire.KeySize]byte
	cfg   Config
	tm    timing
	r     atomic.Uint32 // our ID choice, 0 to 7; a server changes it when another server on its IP uses it
	local netip.AddrPort

	requests atomic.Uint64
	limited  atomic.Uint64
	punchSeq atomic.Uint64 // counts the PUNCHes we relay; their announcer takes each counter once

	dh      *ecdh.PrivateKey // our X25519 key as a storer, for punch secrets
	dhShare [wire.ShareSize]byte

	listen   func() (net.PacketConn, error) // opens birthday sockets
	budget   *punch.Budget
	tl       *kolotransport.Listener
	sl       *kolosecure.Listener
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	once     sync.Once
	closeErr error
	inflight chan struct{}
	accepted chan *kolosecure.Conn

	mu           sync.Mutex
	closed       bool
	table        *table.Table
	store        *records.Store
	tokens       *token.Secret
	limiter      *ratelimit.Limiter
	considers    *ratelimit.Limiter
	verifies     *ratelimit.Limiter
	calls        map[uint64]*call
	nat          *natState
	selfIP       netip.Addr
	lastR        time.Time
	clientID     table.ID
	boot         []netip.AddrPort
	checks       map[netip.AddrPort]bool
	announces    map[Topic]*announcement
	claims       map[[wire.KeySize]byte]chan *kolosecure.Conn
	watchers     map[[wire.KeySize]byte][]chan netip.Addr
	sessions     map[[wire.PunchIDSize]byte]*session
	sessionHosts map[netip.Prefix]int
	relayHosts   map[netip.Prefix]int
	relayTargets map[[wire.KeySize]byte]int
	relaying     int
	punching     int
	held         []*kolosecure.Conn // live connections that punched answers made on birthday sockets of their own
	pending      []netip.Addr       // requester IPs of the birthday punches running, each with a place in held
}

type call struct {
	to  netip.AddrPort
	typ wire.Type
	ch  chan wire.Message
}

// Stats is a snapshot of a node's state and counters; the counters only grow, so callers take differences.
type Stats struct {
	// Servers is the number of servers in the routing table.
	Servers int
	// Records is the number of records this server stores.
	Records int
	// Requests counts the requests that passed the rate limits since New.
	Requests uint64
	// Limited counts the requests the rate limits dropped since New.
	Limited uint64
}

// Stats returns the node's current state and counters; it is safe during traffic and after Close.
func (n *Node) Stats() Stats {
	n.mu.Lock()
	st := Stats{Servers: n.table.Len()}
	if n.store != nil {
		st.Records = n.store.Len(time.Now())
	}
	n.mu.Unlock()
	st.Requests, st.Limited = n.requests.Load(), n.limited.Load()
	return st
}

// New opens a UDP socket on addr, such as "127.0.0.1:0" or ":4000", for the DHT and for kolo-secure connections as id.
// kolo-dht is IPv4 only: an IPv6 addr, IPv4-mapped included, is ErrInvalidArgument.
func New(ctx context.Context, addr string, id *koloid.Identity, cfg *Config) (*Node, error) {
	if id.PublicKey() == nil {
		return nil, fmt.Errorf("%w: nil or zero identity", ErrInvalidArgument)
	}
	addr, err := listenAddr(addr)
	if err != nil {
		return nil, err
	}
	c, err := cfg.withDefaults()
	if err != nil {
		return nil, err
	}
	tc, _ := c.transport()
	tl, err := kolotransport.Listen(ctx, addr, tc)
	if err != nil {
		return nil, wrapConfig(err)
	}
	var ip net.IP
	if ua, ok := tl.Addr().(*net.UDPAddr); ok {
		ip = ua.IP
	}
	listen := func() (net.PacketConn, error) { return net.ListenUDP("udp4", &net.UDPAddr{IP: ip}) }
	return start(tl, listen, id, c, defaultTiming, -1)
}

// listenAddr refuses an IPv6 host, IPv4-mapped included; kolo-transport reports any other bad address.
func listenAddr(addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, nil
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return addr, nil
	}
	if !ip.Is4() {
		return "", errIPv6("listen address")
	}
	return net.JoinHostPort(ip.String(), port), nil
}

// errIPv6 is ErrInvalidArgument for an IPv6 address, IPv4-mapped included, given as what.
func errIPv6(what string) error {
	return fmt.Errorf("%w: IPv6 %s (IPv4-mapped included), and kolo-dht is IPv4 only", ErrInvalidArgument, what)
}

// newConn is New on a caller's socket, such as the network simulator's, with test timing; listen opens birthday
// sockets (nil: none) and r < 0 picks r at random.
func newConn(ctx context.Context, pc net.PacketConn, listen func() (net.PacketConn, error), id *koloid.Identity, cfg *Config, tm timing, r int) (*Node, error) {
	if id.PublicKey() == nil {
		pc.Close()
		return nil, fmt.Errorf("%w: nil or zero identity", ErrInvalidArgument)
	}
	c, err := cfg.withDefaults()
	if err != nil {
		pc.Close()
		return nil, err
	}
	tc, _ := c.transport()
	tl, err := kolotransport.ListenConn(ctx, pc, tc)
	if err != nil {
		return nil, wrapConfig(err)
	}
	return start(tl, listen, id, c, tm, r)
}

func wrapConfig(err error) error {
	if errors.Is(err, kolotransport.ErrInvalidConfig) || errors.Is(err, kolosecure.ErrInvalidConfig) {
		return fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	return err
}

func start(tl *kolotransport.Listener, listen func() (net.PacketConn, error), id *koloid.Identity, c Config, tm timing, r int) (*Node, error) {
	_, sc := c.transport()
	sl, err := kolosecure.NewListener(tl, id, sc)
	if err != nil {
		return nil, wrapConfig(err)
	}
	dh, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		sl.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	now := time.Now()
	n := &Node{
		id:      id,
		cfg:     c,
		tm:      tm,
		listen:  listen,
		dh:      dh,
		dhShare: [wire.ShareSize]byte(dh.PublicKey().Bytes()),
		budget: punch.NewBudget(punch.Limits{
			Punches: c.MaxRandomPunches, PerTarget: c.MaxRandomPunchesPerTarget, PerRequester: c.MaxRandomPunchesPerRequester,
			Sockets: c.MaxPunchSockets, Interval: c.RandomPunchInterval, Cooldown: c.RandomPunchCooldown, PerMinute: c.MaxRandomPunchesPerMinute,
		}),
		tl:           tl,
		sl:           sl,
		ctx:          ctx,
		cancel:       cancel,
		inflight:     make(chan struct{}, c.MaxInflight),
		accepted:     make(chan *kolosecure.Conn, c.acceptQueue()),
		tokens:       token.New(now),
		nat:          newNAT(tm.sampleAge),
		limiter:      ratelimit.New(c.MaxRequestsPerIP, c.MaxRequestsPerPrefix, c.MaxRequests, now),
		considers:    ratelimit.New(1, 4, maxChecks*4, now),
		verifies:     ratelimit.New(min(c.MaxRequestsPerIP, maxVerifiesPerIP), min(c.MaxRequestsPerPrefix, maxVerifiesPerPrefix), min(c.MaxRequests, maxVerifies), now),
		calls:        make(map[uint64]*call),
		checks:       make(map[netip.AddrPort]bool),
		announces:    make(map[Topic]*announcement),
		claims:       make(map[[wire.KeySize]byte]chan *kolosecure.Conn),
		watchers:     make(map[[wire.KeySize]byte][]chan netip.Addr),
		sessions:     make(map[[wire.PunchIDSize]byte]*session),
		sessionHosts: make(map[netip.Prefix]int),
		relayHosts:   make(map[netip.Prefix]int),
		relayTargets: make(map[[wire.KeySize]byte]int),
	}
	copy(n.key[:], id.PublicKey())
	if r < 0 {
		var b [1]byte
		rand.Read(b[:])
		r = int(b[0])
	}
	n.r.Store(uint32(r) & 7)
	rand.Read(n.clientID[:])
	if ua, ok := tl.Addr().(*net.UDPAddr); ok {
		ap := ua.AddrPort()
		n.local = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()) // the OS may report an IPv4 socket in 16 bytes
		n.selfIP = n.local.Addr()
	}
	n.table = table.New(n.selfID())
	if c.Server {
		n.store = records.NewStore(records.Limits{Records: c.MaxRecords, PerTopic: c.MaxRecordsPerTopic, PerHost: c.MaxRecordsPerIP, PerGroup: perGroup(c.MaxRecordsPerTopic), TTL: tm.ttl})
	}
	n.wg.Add(3)
	go n.readLoop()
	go n.acceptLoop()
	go n.maintainLoop()
	return n, nil
}

// spawn runs f in a goroutine that Close waits for, unless the node is closed.
func (n *Node) spawn(f func()) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return false
	}
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		f()
	}()
	return true
}

// selfID is our routing ID: derived from our public IP for a server, random for a client. Call with mu held.
func (n *Node) selfID() table.ID {
	if n.cfg.Server {
		return table.NodeID(n.selfIP, uint8(n.r.Load()))
	}
	return n.clientID
}

func (n *Node) flags() wire.Flags { return wire.NewFlags(uint8(n.r.Load()), n.cfg.Server) }

// own reports whether ap is our socket's address or an address servers saw for us. Call with mu held.
func (n *Node) own(ap netip.AddrPort) bool {
	return ap == n.local || n.nat.observed(ap)
}

// collide moves a server to another r when another server on our IP, which answered a request of ours, uses ours:
// both would have one ID. At most one change per rChange. Call with mu held.
func (n *Node) collide(from netip.AddrPort, f wire.Flags, now time.Time) {
	if !n.cfg.Server || !f.Server() || from.Addr() != n.selfIP || uint32(f.R()) != n.r.Load() || n.own(from) ||
		(!n.lastR.IsZero() && now.Sub(n.lastR) < n.tm.rChange) {
		return
	}
	var b [1]byte
	rand.Read(b[:])
	n.r.Store((n.r.Load() + 1 + uint32(b[0])%7) & 7)
	n.lastR = now
	n.table.SetSelf(n.selfID())
}

// Addr returns the local address of the node's socket.
func (n *Node) Addr() net.Addr { return n.tl.Addr() }

// Close stops announcing, closes the socket and every connection of the node, and waits for its goroutines.
// It is safe to call more than once.
func (n *Node) Close() error {
	n.once.Do(func() {
		n.mu.Lock()
		n.closed = true
		n.mu.Unlock()
		n.cancel()
		n.closeErr = n.sl.Close()
		n.wg.Wait()
		for len(n.accepted) > 0 {
			(<-n.accepted).Close()
		}
	})
	return n.closeErr
}

// Accept waits for the next inbound connection, punched or direct, that no Connect in progress claimed.
// Unclaimed connections wait in a queue of Secure.MaxPending (default 64); when it is full, new ones are closed.
func (n *Node) Accept(ctx context.Context) (*kolosecure.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case c := <-n.accepted:
		return c, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-n.ctx.Done():
		return nil, ErrClosed
	}
}

func (n *Node) acceptLoop() {
	defer n.wg.Done()
	for {
		c, err := n.sl.Accept(n.ctx)
		if err != nil {
			return
		}
		key := [wire.KeySize]byte(c.RemotePublicKey())
		n.mu.Lock()
		n.connected(c)
		if ch, ok := n.claims[key]; ok {
			delete(n.claims, key)
			ch <- c // buffered and sent under mu, so a Connect that gives up never misses it
			n.mu.Unlock()
			continue
		}
		n.mu.Unlock()
		n.enqueue(c)
	}
}

func (n *Node) enqueue(c *kolosecure.Conn) {
	select {
	case n.accepted <- c:
	default:
		c.CloseWithError(1, "")
	}
}

// connected ends the waits of the punches answered for c's key: c, accepted or dialed, is the connection they wait
// for. Call with mu held.
func (n *Node) connected(c *kolosecure.Conn) {
	key := [wire.KeySize]byte(c.RemotePublicKey())
	for _, w := range n.watchers[key] {
		w <- remoteIP(c) // buffered, and each watcher gets one connection
	}
	delete(n.watchers, key)
}

// watch returns a channel that gets the IP of the next connection with key, accepted or dialed. Call with mu held.
func (n *Node) watch(key [wire.KeySize]byte) chan netip.Addr {
	w := make(chan netip.Addr, 1)
	n.watchers[key] = append(n.watchers[key], w)
	return w
}

func (n *Node) unwatch(key [wire.KeySize]byte, w chan netip.Addr) {
	n.mu.Lock()
	defer n.mu.Unlock()
	ws := n.watchers[key]
	for i, x := range ws {
		if x == w {
			ws = append(ws[:i], ws[i+1:]...)
			break
		}
	}
	if len(ws) == 0 {
		delete(n.watchers, key)
	} else {
		n.watchers[key] = ws
	}
}

func (n *Node) readLoop() {
	defer n.wg.Done()
	buf := make([]byte, kolotransport.MaxPacketSize)
	for {
		k, from, err := n.tl.ReadPacket(n.ctx, buf)
		if err != nil {
			return
		}
		n.handlePacket(buf[:k], from, time.Now())
	}
}

func randID() uint64 {
	var b [8]byte
	rand.Read(b[:])
	return binary.LittleEndian.Uint64(b[:])
}

func (n *Node) begin(to netip.AddrPort, m wire.Message, pad int) (uint64, *call, error) {
	if !addrs.Usable(to) {
		return 0, nil, errUnusable
	}
	c := &call{to: to, typ: m.Type(), ch: make(chan wire.Message, 1)}
	n.mu.Lock()
	id := randID()
	for n.calls[id] != nil {
		id = randID()
	}
	n.calls[id] = c
	n.mu.Unlock()
	b, err := wire.Encode(id, m, pad)
	if err == nil {
		err = n.tl.WritePacket(b, to)
	}
	if err != nil {
		n.end(id)
		if n.ctx.Err() != nil {
			return 0, nil, ErrClosed
		}
		return 0, nil, err
	}
	return id, c, nil
}

func (n *Node) end(id uint64) {
	n.mu.Lock()
	delete(n.calls, id)
	n.mu.Unlock()
}

// ctxErr is ctx.Err, but a deadline already past counts as DeadlineExceeded: on a coarse timer (Windows, a busy VM)
// ctx.Err lags a request's own timeout.
func ctxErr(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if d, ok := ctx.Deadline(); ok && !time.Now().Before(d) {
		return context.DeadlineExceeded
	}
	return nil
}

func (n *Node) await(ctx context.Context, c *call, timeout time.Duration) (wire.Message, error) {
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case r := <-c.ch:
		return r, nil
	case <-t.C:
		return nil, errTimeout
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-n.ctx.Done():
		return nil, ErrClosed
	}
}

// request sends m to to, padded to pad bytes, and waits up to timeout for its reply, within MaxInflight.
func (n *Node) request(ctx context.Context, to netip.AddrPort, m wire.Message, pad int, timeout time.Duration) (wire.Message, error) {
	select {
	case n.inflight <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-n.ctx.Done():
		return nil, ErrClosed
	}
	defer func() { <-n.inflight }()
	return n.unbudgeted(ctx, to, m, pad, timeout)
}

// unbudgeted is request outside MaxInflight, for relays, which MaxRelays bounds.
func (n *Node) unbudgeted(ctx context.Context, to netip.AddrPort, m wire.Message, pad int, timeout time.Duration) (wire.Message, error) {
	id, c, err := n.begin(to, m, pad)
	if err != nil {
		return nil, err
	}
	defer n.end(id)
	return n.await(ctx, c, timeout)
}

// send writes m to to in at most size bytes, drops errors as UDP loss would, and returns the bytes sent, 0 on failure.
func (n *Node) send(to netip.AddrPort, m wire.Message, size int) int {
	b, err := wire.Fit(0, m, size)
	if err != nil || n.tl.WritePacket(b, to) != nil {
		return 0
	}
	return len(b)
}

// reply sends m as the reply to request id, in at most size bytes, and returns the bytes sent.
func (n *Node) reply(id uint64, m wire.Message, to netip.AddrPort, size int) int {
	b, err := wire.Fit(id, m, size)
	if err != nil || n.tl.WritePacket(b, to) != nil {
		return 0
	}
	return len(b)
}

// handlePacket processes one datagram: a reply must match a pending request's id, type and exact source, an IPv6
// source or our own request coming back is dropped, and requests pass the rate limits before decoding.
func (n *Node) handlePacket(b []byte, from netip.AddrPort, now time.Time) {
	typ, id, ok := wire.Peek(b)
	if !ok || !addrs.IPv4(from) {
		return
	}
	if !wire.IsRequest(typ) && typ != wire.TypeProbe {
		n.mu.Lock()
		c := n.calls[id]
		n.mu.Unlock()
		if c == nil || c.to != from || wire.ReplyType(c.typ) != typ {
			return
		}
		_, m, err := wire.Decode(b)
		if err != nil {
			return
		}
		n.mu.Lock()
		if n.calls[id] != c {
			n.mu.Unlock()
			return
		}
		delete(n.calls, id)
		n.mu.Unlock()
		n.observe(from, m, now)
		c.ch <- m
		return
	}
	n.mu.Lock()
	if c := n.calls[id]; c != nil && c.to == from && c.typ == typ {
		n.mu.Unlock()
		return
	}
	allowed := n.limiter.Allow(from.Addr(), now)
	n.mu.Unlock()
	if !allowed {
		n.limited.Add(1)
		return
	}
	n.requests.Add(1)
	_, m, err := wire.Decode(b)
	if err != nil {
		return
	}
	n.serve(id, m, from, len(b), now)
}

// observe learns from a reply of a server: our address as it saw it, and the server itself for the table.
func (n *Node) observe(from netip.AddrPort, m wire.Message, now time.Time) {
	var f wire.Flags
	var obs netip.AddrPort
	switch m := m.(type) {
	case *wire.PingReply:
		f, obs = m.Flags, m.Observed
	case *wire.FindNodeReply:
		f, obs = m.Flags, m.Observed
	case *wire.LookupReply:
		f, obs = m.Flags, m.Observed
	default:
		return
	}
	if !f.Server() {
		return
	}
	n.mu.Lock()
	n.collide(from, f, now)
	n.nat.add(from, obs, now)
	if ip, ok := n.nat.publicIP(); ok && n.cfg.Server && ip != n.selfIP && n.nat.ipCount(ip) > n.nat.ipCount(n.selfIP) {
		n.selfIP = ip
		n.table.SetSelf(n.selfID())
	}
	n.mu.Unlock()
	n.verified(from, f.R(), now)
}

// verified adds a server that answered us; a full bucket pings its oldest entry and keeps it if it answers.
func (n *Node) verified(addr netip.AddrPort, r uint8, now time.Time) {
	n.mu.Lock()
	if n.own(addr) {
		n.mu.Unlock()
		return
	}
	v, oldest := n.table.Insert(addr, r, now)
	if v != table.Full || n.checks[oldest.Addr] || len(n.checks) >= maxChecks {
		n.mu.Unlock()
		return
	}
	n.checks[oldest.Addr] = true
	n.mu.Unlock()
	n.ping(oldest.Addr, pingSize, func(ok bool) {
		if !ok {
			n.mu.Lock()
			n.table.Replace(oldest.ID, addr, r, time.Now())
			n.mu.Unlock()
		}
	})
}

// consider pings a server that sent us a request, if the table could take it, the request left room for the ping
// beside its reply, and the per-network budget allows; its reply adds it.
func (n *Node) consider(from netip.AddrPort, f wire.Flags, room int, now time.Time) {
	if !f.Server() || room < checkSize {
		return
	}
	n.mu.Lock()
	if n.own(from) || !n.considers.Allow(from.Addr(), now) {
		n.mu.Unlock()
		return
	}
	v, _ := n.table.Check(from, f.R(), now)
	if (v != table.Added && v != table.Full) || n.checks[from] || len(n.checks) >= maxChecks {
		n.mu.Unlock()
		return
	}
	n.checks[from] = true
	n.mu.Unlock()
	n.ping(from, checkSize, nil)
}

// ping sends a PING of size bytes to addr at once and waits for it in the background, then calls done.
// addr must be marked in checks; the mark is removed when the ping ends.
func (n *Node) ping(addr netip.AddrPort, size int, done func(ok bool)) {
	unmark := func() {
		n.mu.Lock()
		delete(n.checks, addr)
		n.mu.Unlock()
	}
	select {
	case n.inflight <- struct{}{}:
	default:
		unmark()
		return
	}
	id, c, err := n.begin(addr, &wire.Ping{Flags: n.flags()}, size)
	if err != nil {
		<-n.inflight
		unmark()
		return
	}
	ok := n.spawn(func() {
		defer func() { <-n.inflight }()
		defer unmark()
		defer n.end(id)
		_, err := n.await(n.ctx, c, n.cfg.RequestTimeout)
		if done != nil && n.ctx.Err() == nil {
			done(err == nil)
		}
	})
	if !ok {
		n.end(id)
		<-n.inflight
		unmark()
	}
}

func (n *Node) failed(addr netip.AddrPort, r uint8) {
	n.mu.Lock()
	n.table.Failed(table.NodeID(addr.Addr(), r), addr)
	n.mu.Unlock()
}

func (n *Node) maintainLoop() {
	defer n.wg.Done()
	t := time.NewTicker(n.tm.maintain)
	defer t.Stop()
	for {
		select {
		case <-n.ctx.Done():
			return
		case <-t.C:
		}
		n.mu.Lock()
		stale := n.table.Stale(time.Now(), staleChecks)
		empty := n.table.Len() == 0
		boot := append([]netip.AddrPort(nil), n.boot...)
		n.mu.Unlock()
		for _, e := range stale {
			if _, err := n.request(n.ctx, e.Addr, &wire.Ping{Flags: n.flags()}, pingSize, n.cfg.RequestTimeout); err != nil && n.ctx.Err() == nil {
				n.failed(e.Addr, e.R)
			}
		}
		if empty {
			for _, b := range boot {
				n.request(n.ctx, b, &wire.Ping{Flags: n.flags()}, pingSize, n.cfg.RequestTimeout)
			}
		}
	}
}

// nodesFor returns the servers closest to target that may be shown to a requester at to. Call with mu held.
func (n *Node) nodesFor(target table.ID, to netip.AddrPort) []wire.Node {
	var out []wire.Node
	for _, e := range n.table.Closest(target, table.K+1) {
		if e.Addr != to && addrs.AllowedFrom(e.Addr, to.Addr()) && len(out) < wire.MaxNodes {
			out = append(out, wire.Node{Flags: wire.NewFlags(e.R, true), Addr: e.Addr})
		}
	}
	return out
}

// serve answers one request; size is the request's length, which the reply and any check ping together never exceed.
func (n *Node) serve(id uint64, m wire.Message, from netip.AddrPort, size int, now time.Time) {
	switch m := m.(type) {
	case *wire.Ping:
		n.mu.Lock()
		tok := n.tokens.Make(from, now)
		n.mu.Unlock()
		sent := n.reply(id, &wire.PingReply{Observed: from, Token: tok, Flags: n.flags()}, from, size)
		if sent > 0 {
			n.consider(from, m.Flags, size-sent, now)
		}
	case *wire.FindNode:
		if !n.cfg.Server {
			return
		}
		n.mu.Lock()
		tok := n.tokens.Make(from, now)
		nodes := n.nodesFor(m.Target, from)
		n.mu.Unlock()
		sent := n.reply(id, &wire.FindNodeReply{Observed: from, Token: tok, Flags: n.flags(), Nodes: nodes}, from, size)
		if sent > 0 {
			n.consider(from, m.Flags, size-sent, now)
		}
	case *wire.Lookup:
		if !n.cfg.Server {
			return
		}
		n.mu.Lock()
		tok := n.tokens.Make(from, now)
		nodes := n.nodesFor(table.ID(m.Topic), from)
		var recs []wire.Record
		for _, r := range n.store.Get(m.Topic, wire.MaxRecords, now) {
			if addrs.AllowedFrom(r.Addr, from.Addr()) {
				age := min(now.Sub(r.Refreshed)/time.Second, wire.MaxAge)
				recs = append(recs, wire.Record{Key: r.Key, Addr: r.Addr, Age: uint16(age), Sig: r.Sig})
			}
		}
		n.mu.Unlock()
		sent := n.reply(id, &wire.LookupReply{Observed: from, Token: tok, Flags: n.flags(), Nodes: nodes, Records: recs}, from, size)
		if sent > 0 {
			n.consider(from, m.Flags, size-sent, now)
		}
	case *wire.Announce:
		if !n.cfg.Server {
			return
		}
		if out := n.storeAnnounce(m, from, now); out != nil {
			n.reply(id, out, from, size)
		}
	case *wire.Connect:
		if n.cfg.Server && size >= wire.MaxSize-1 {
			n.relay(id, m, from, size, now)
		}
	case *wire.Punch:
		n.punched(id, m, from, size)
	case *wire.Probe:
		n.onProbe(m, from, size)
	}
}

// Most ANNOUNCEs per second one IPv4 address, one /24 and everyone may make that cost a key agreement or a signature
// check (about 50us each, so at most about 5% of a core). A refresh of a stored record costs neither and is not counted.
const (
	maxVerifiesPerIP     = 20
	maxVerifiesPerPrefix = 100
	maxVerifies          = 1000
)

// storeAnnounce stores or refreshes the announced record and returns the reply, or nil when the sender is over its
// verification budget, so it times out and tries again at its next refresh. The key agreement and the signature
// check run without n.mu.
func (n *Node) storeAnnounce(m *wire.Announce, from netip.AddrPort, now time.Time) *wire.AnnounceReply {
	n.mu.Lock()
	out := &wire.AnnounceReply{Observed: from, Token: n.tokens.Make(from, now), Share: n.dhShare}
	switch {
	case !n.tokens.Check(from, m.Token, now):
		out.Status = wire.StatusBadToken
		n.mu.Unlock()
		return out
	case m.Addr != from:
		out.Status = wire.StatusRefused
		n.mu.Unlock()
		return out
	}
	// A refresh with the same share keeps the secret, so only a new share costs a key agreement.
	old, found := n.store.Find(m.Topic, m.Key, now)
	newShare := !found || old.Share != m.Share
	changed := newShare || old.Addr != from || old.Sig != m.Sig
	if changed && !n.verifies.Allow(from.Addr(), now) {
		n.limited.Add(1)
		n.mu.Unlock()
		return nil
	}
	n.mu.Unlock()

	r := records.Record{Topic: m.Topic, Key: m.Key, Addr: from, Sig: m.Sig, Share: m.Share, Secret: old.Secret}
	if newShare {
		var ok bool
		if r.Secret, ok = punchSecret(n.dh, m.Share, m.Share, n.dhShare, m.Key, m.Topic); !ok {
			out.Status = wire.StatusRefused
			return out
		}
	}
	// An unchanged record is the one already verified, so only a changed one is checked.
	if changed && !records.Verify(r) {
		out.Status = wire.StatusRefused
		return out
	}
	n.mu.Lock()
	res := n.store.PutVerified(r, now)
	n.mu.Unlock()
	switch res {
	case records.Stored, records.Refreshed:
		out.Status = wire.StatusOK
	case records.Full:
		out.Status = wire.StatusFull
	default:
		out.Status = wire.StatusRefused
	}
	return out
}

func samePublicKey(a ed25519.PublicKey, b [wire.KeySize]byte) bool {
	return len(a) == wire.KeySize && [wire.KeySize]byte(a) == b
}
