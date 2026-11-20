package kolodht

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/ciranda-dev/kolo-dht/internal/addrs"
	"github.com/ciranda-dev/kolo-dht/internal/punch"
	"github.com/ciranda-dev/kolo-dht/internal/wire"
	koloid "github.com/ciranda-dev/kolo-id"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

// session is one punch attempt. An address counts as proved once it echoes our nonce from an address we sent it to.
type session struct {
	pid     [wire.PunchIDSize]byte
	nonce   [wire.PunchIDSize]byte
	host    netip.Prefix
	sentTo  []netip.AddrPort
	replies int
	echoed  bool
	valid   chan proof
}

// proof is an address that echoed our nonce and the socket it reached: 0 is the node's, i > 0 birthday socket i.
type proof struct {
	addr   netip.AddrPort
	holder int
}

const maxSentTo = 8

// openSession starts a session toward dest, at most maxDestAttempts per destination host. Call with mu held.
func (n *Node) openSession(pid [wire.PunchIDSize]byte, dest netip.AddrPort) (*session, bool) {
	h := addrs.Host(dest.Addr())
	if n.sessions[pid] != nil || n.sessionHosts[h] >= maxDestAttempts {
		return nil, false
	}
	s := &session{pid: pid, host: h, valid: make(chan proof, 1)}
	for s.nonce == [wire.PunchIDSize]byte{} {
		rand.Read(s.nonce[:])
	}
	n.sessions[pid] = s
	n.sessionHosts[h]++
	return s, true
}

// dropSession is closeSession with mu held.
func (n *Node) dropSession(s *session) {
	if n.sessions[s.pid] == s {
		delete(n.sessions, s.pid)
		if n.sessionHosts[s.host]--; n.sessionHosts[s.host] <= 0 {
			delete(n.sessionHosts, s.host)
		}
	}
}

func (n *Node) closeSession(s *session) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.dropSession(s)
}

// probe sends one probe with our nonce to addr and remembers that addr got it.
func (n *Node) probe(s *session, addr netip.AddrPort) {
	n.mu.Lock()
	if !slices.Contains(s.sentTo, addr) && len(s.sentTo) < maxSentTo {
		s.sentTo = append(s.sentTo, addr)
	}
	n.mu.Unlock()
	if k := n.send(addr, &wire.Probe{PunchID: s.pid, Nonce: s.nonce}, wire.MaxSize); k > 0 {
		n.trace(TraceEvent{Kind: TraceProbeSent, Local: n.localAddr(), Remote: addr, Size: k})
	}
}

// handle passes on a proof and returns the answer to m, if any: at most maxProbeReplies per session, none after an
// echo once we have answered. Call with mu held.
func (s *session) handle(m *wire.Probe, from netip.AddrPort, holder int, proves bool) *wire.Probe {
	if proves {
		select {
		case s.valid <- proof{from, holder}:
		default:
		}
		if s.echoed {
			return nil
		}
	}
	if m.Nonce == [wire.PunchIDSize]byte{} || s.replies >= maxProbeReplies {
		return nil
	}
	s.replies++
	s.echoed = true
	return &wire.Probe{PunchID: s.pid, Nonce: s.nonce, Echo: m.Nonce}
}

// onProbe handles a probe on the node socket; the answer goes out in a datagram the size of the one received.
func (n *Node) onProbe(m *wire.Probe, from netip.AddrPort, size int) {
	n.mu.Lock()
	s := n.sessions[m.PunchID]
	if s == nil {
		n.mu.Unlock()
		return
	}
	proves := m.Echo == s.nonce && slices.Contains(s.sentTo, from)
	reply := s.handle(m, from, 0, proves)
	// The answer carries our nonce to from, so a later echo proves only from's own real address.
	if reply != nil && !slices.Contains(s.sentTo, from) && len(s.sentTo) < maxSentTo {
		s.sentTo = append(s.sentTo, from)
	}
	n.mu.Unlock()
	local := n.localAddr()
	n.trace(TraceEvent{Kind: TraceProbeReceived, Local: local, Remote: from, Size: size})
	if proves {
		n.trace(TraceEvent{Kind: TraceProved, Local: local, Remote: from})
	}
	if reply == nil {
		return
	}
	if k := n.send(from, reply, size); k > 0 {
		n.trace(TraceEvent{Kind: TraceProbeSent, Local: local, Remote: from, Size: k})
	}
}

// run starts f in a node goroutine and returns a function, safe to call twice, that stops f and waits for it.
func (n *Node) run(f func(stop <-chan struct{})) (func(), bool) {
	stop, done := make(chan struct{}), make(chan struct{})
	if !n.spawn(func() { defer close(done); f(stop) }) {
		return nil, false
	}
	var once sync.Once
	return func() { once.Do(func() { close(stop); <-done }) }, true
}

// randomProbes sends the random-port probes of s to ip, the peer's verified IP.
func (n *Node) randomProbes(ctx context.Context, stop <-chan struct{}, s *session, ip netip.Addr) {
	p := &wire.Probe{PunchID: s.pid, Nonce: s.nonce}
	local := n.localAddr()
	n.trace(TraceEvent{Kind: TraceRandomProbes, Local: local, Remote: netip.AddrPortFrom(ip, 0), Count: punch.RandomTries})
	punch.RandomProbes(ctx, stop, ip, n.tm.randomEvery, punch.RandomTries, func() uint16 { return n.tm.randomPort(ip) }, func(ap netip.AddrPort) {
		if k := n.send(ap, p, wire.MaxSize); k > 0 {
			n.trace(TraceEvent{Kind: TraceProbeSent, Local: local, Remote: ap, Size: k})
		}
	})
}

// birthday is the random side of a punch: the node socket (holder 0) and 255 new sockets, all sending only to peer.
type birthday struct {
	n     *Node
	s     *session
	g     *punch.Grant
	peer  netip.AddrPort
	probe []byte

	mu   sync.Mutex
	pool *punch.Pool
	// Until the peer reaches a holder only holder 0 probes at the default TTL, so a wrong stored address gets one probe.
	seen bool
}

// openBirthday opens the holders and sends the first probe from each. At TTL 5 it opens our NAT toward peer and
// dies before the peer's NAT.
func (n *Node) openBirthday(s *session, peer netip.AddrPort, g *punch.Grant) (*birthday, error) {
	b := &birthday{n: n, s: s, g: g, peer: peer}
	b.probe, _ = wire.Encode(0, &wire.Probe{PunchID: s.pid, Nonce: s.nonce}, 0)
	if n.listen == nil {
		g.ReleaseSockets(punch.Sockets - 1)
		return nil, ErrTryLater
	}
	pool, err := punch.Open(punch.Sockets-1, n.listen, punch.LowTTL, peer, n.spawn, b.onPacket)
	if err != nil {
		g.ReleaseSockets(punch.Sockets - 1)
		if errors.Is(err, punch.ErrClosed) {
			return nil, ErrClosed
		}
		return nil, ErrTryLater
	}
	b.mu.Lock()
	b.pool = pool
	b.mu.Unlock()
	n.trace(TraceEvent{Kind: TraceBirthdayOpened, Local: n.localAddr(), Remote: peer, Count: pool.Len() + 1})
	n.probe(s, peer)
	for i := range pool.Len() {
		if pool.Send(i, b.probe) == nil {
			b.traceSent(pool, i, len(b.probe), punch.LowTTL)
		}
	}
	return b, nil
}

func (b *birthday) traceSent(pool *punch.Pool, i, size, ttl int) {
	if b.n.cfg.Trace != nil {
		b.n.trace(TraceEvent{Kind: TraceProbeSent, Local: pool.LocalAddr(i), Remote: b.peer, Size: size, TTL: ttl})
	}
}

func (b *birthday) onPacket(i int, buf []byte, from netip.AddrPort) {
	_, m, err := wire.Decode(buf)
	p, ok := m.(*wire.Probe)
	if err != nil || !ok || p.PunchID != b.s.pid {
		return
	}
	proves := p.Echo == b.s.nonce
	b.n.mu.Lock()
	reply := b.s.handle(p, from, i+1, proves)
	b.n.mu.Unlock()
	sent := 0
	b.mu.Lock()
	b.seen = true
	pool := b.pool
	if reply != nil && pool != nil {
		if out, err := wire.Fit(0, reply, len(buf)); err == nil {
			pool.SetTTL(i, punch.DefaultTTL)
			if pool.Send(i, out) == nil {
				sent = len(out)
			}
		}
	}
	b.mu.Unlock()
	if pool == nil || b.n.cfg.Trace == nil {
		return
	}
	local := pool.LocalAddr(i)
	b.n.trace(TraceEvent{Kind: TraceProbeReceived, Local: local, Remote: from, Size: len(buf)})
	if proves {
		b.n.trace(TraceEvent{Kind: TraceProved, Local: local, Remote: from})
	}
	if sent > 0 {
		b.traceSent(pool, i, sent, punch.DefaultTTL)
	}
}

func (b *birthday) keepAlive(ctx context.Context, stop <-chan struct{}) {
	punch.Birthday(ctx, stop, b.n.tm.keepAliveDelay, b.n.tm.randomEvery, punch.RandomTries, punch.Sockets, punch.LowTTL, func(i, ttl int) {
		b.mu.Lock()
		if !b.seen {
			if i == 0 {
				b.mu.Unlock()
				return
			}
			ttl = punch.LowTTL
		}
		if i == 0 {
			b.mu.Unlock()
			b.n.probe(b.s, b.peer)
			return
		}
		pool := b.pool
		pool.SetTTL(i-1, ttl)
		err := pool.Send(i-1, b.probe)
		b.mu.Unlock()
		if err == nil {
			b.traceSent(pool, i-1, len(b.probe), ttl)
		}
	})
}

func (b *birthday) close() {
	b.mu.Lock()
	pool := b.pool
	b.mu.Unlock()
	if pool != nil {
		b.g.ReleaseSockets(pool.Close())
	}
}

// dial commits the holder of p, closes the other sockets and gives the winner its own listener.
func (b *birthday) dial(ctx context.Context, p proof, key []byte) (*kolosecure.Conn, error) {
	n := b.n
	if p.holder == 0 {
		b.close()
		return n.sl.Dial(ctx, p.addr, key)
	}
	pc, err := b.pool.Take(p.holder - 1)
	b.close()
	// The winner leaves the budget once its connection is up or failed; its socket lives on with the connection.
	defer b.g.ReleaseSockets(1)
	var tl *kolotransport.Listener
	if err == nil {
		tc, _ := n.cfg.transport()
		tl, err = kolotransport.ListenConn(ctx, pc, tc)
	}
	var sl *kolosecure.Listener
	if err == nil {
		_, sc := n.cfg.transport()
		sl, err = kolosecure.NewListener(tl, n.id, sc)
	}
	if err != nil {
		return nil, err
	}
	c, err := sl.Dial(ctx, p.addr, key)
	if err == nil && !n.spawn(func() {
		select {
		case <-c.Context().Done():
		case <-n.ctx.Done():
		}
		sl.Close()
	}) {
		err = ErrClosed
	}
	if err != nil {
		sl.Close()
		return nil, err
	}
	return c, nil
}

// punchContext is the first input of a PUNCH MAC.
const punchContext = "kolo-dht/punch/v1"

// punchMAC is HMAC-SHA256 under the punch secret of punchContext and p encoded with a zero MAC.
func punchMAC(secret [32]byte, p *wire.Punch) ([wire.MACSize]byte, bool) {
	q := *p
	q.MAC = [wire.MACSize]byte{}
	b, err := wire.Encode(0, &q, 0)
	if err != nil {
		return [wire.MACSize]byte{}, false
	}
	h := hmac.New(sha256.New, secret[:])
	h.Write([]byte(punchContext))
	h.Write(b)
	return [wire.MACSize]byte(h.Sum(nil)), true
}

// relay forwards a CONNECT from a validated requester to the announcer it names, and returns the announcer's answer.
// Relays have their own budget (MaxRelays), with at most maxRelaysPerHost per requester host and maxRelaysPerTarget per target.
func (n *Node) relay(id uint64, m *wire.Connect, from netip.AddrPort, size int, now time.Time) {
	host := addrs.Host(from.Addr())
	n.mu.Lock()
	out := &wire.ConnectReply{Observed: from, Token: n.tokens.Make(from, now)}
	if !n.tokens.Check(from, m.Token, now) {
		n.mu.Unlock()
		out.Status = wire.StatusBadToken
		n.reply(id, out, from, size)
		return
	}
	rec, ok := n.store.Find(m.Topic, m.Target, now)
	switch {
	case !ok:
		out.Status = wire.StatusNoRecord
	case n.relaying >= n.cfg.MaxRelays || n.relayHosts[host] >= maxRelaysPerHost || n.relayTargets[m.Target] >= maxRelaysPerTarget:
		out.Status = wire.StatusFull
	}
	// The PUNCH carries our next counter and a MAC under the record's punch secret, so only we can make the announcer act.
	p := &wire.Punch{Flags: n.flags(), Topic: m.Topic, Target: m.Target, Key: m.Key, Addr: from, Class: m.Class, NoRandom: m.NoRandom, PunchID: m.PunchID}
	if out.Status == wire.StatusOK {
		p.Counter = n.punchSeq.Add(1)
		if p.MAC, ok = punchMAC(rec.Secret, p); !ok {
			out.Status = wire.StatusRefused
		}
	}
	if out.Status != wire.StatusOK {
		n.mu.Unlock()
		n.reply(id, out, from, size)
		return
	}
	n.relaying++
	n.relayHosts[host]++
	n.relayTargets[m.Target]++
	n.mu.Unlock()
	release := func() {
		n.mu.Lock()
		defer n.mu.Unlock()
		n.relaying--
		if n.relayHosts[host]--; n.relayHosts[host] <= 0 {
			delete(n.relayHosts, host)
		}
		if n.relayTargets[m.Target]--; n.relayTargets[m.Target] <= 0 {
			delete(n.relayTargets, m.Target)
		}
	}
	ok = n.spawn(func() {
		defer release()
		resp, err := n.unbudgeted(n.ctx, rec.Addr, p, 0, n.cfg.RequestTimeout)
		if err != nil {
			if n.ctx.Err() != nil {
				return
			}
			out.Status = wire.StatusRefused
		} else {
			pr := resp.(*wire.PunchReply)
			out.Status, out.Class, out.Sig = pr.Status, pr.Class, pr.Sig
		}
		n.reply(id, out, from, size)
	})
	if !ok {
		release()
	}
}

// punchAdmission is a PUNCH that passed the MAC and replay check, and what we decided about it. Unless out.Status is
// OK nothing else is set; if it is, the punch counts in n.punching and holds s, g (nil if no burst is needed) and w.
type punchAdmission struct {
	out                *wire.PunchReply
	ip                 netip.Addr // our IP as the storer saw it
	s                  *session
	g                  *punch.Grant
	w                  chan netip.Addr
	ours               wire.Class
	weDial, theyRandom bool
}

// admitPunch checks a PUNCH of a storer and decides the status of its answer; nil means drop it unanswered. A
// random side needs a burst grant, else TryLater.
func (n *Node) admitPunch(m *wire.Punch, from netip.AddrPort) *punchAdmission {
	a := &punchAdmission{out: &wire.PunchReply{}}
	now := time.Now()
	n.mu.Lock()
	var st *storer
	if an := n.announces[Topic(m.Topic)]; an != nil && m.Target == n.key {
		st = an.storers[from]
	}
	if st == nil || !validMAC(st.secret, m) || !st.replay.take(m.Counter) {
		n.mu.Unlock()
		return nil
	}
	a.ip = st.observed.Addr()
	n.mu.Unlock()
	refused := n.refuses(m.Addr)
	n.mu.Lock()
	defer n.mu.Unlock()
	a.ours = n.nat.class(now)
	a.out.Class = a.ours
	switch {
	case m.Key == n.key || !addrs.AllowedFrom(m.Addr, from.Addr()) || refused:
		a.out.Status = wire.StatusRefused
	case a.ours == wire.ClassRandom && (m.Class == wire.ClassRandom || m.NoRandom):
		a.out.Status = wire.StatusUnreachable
	case a.ours == wire.ClassRandom && !n.canHold(m.Addr.Addr()):
		// Its connection could not be held, so do not open sockets for it.
		a.out.Status = wire.StatusTryLater
	case n.punching >= n.cfg.MaxPunches:
		a.out.Status = wire.StatusFull
	default:
		var ok bool
		if a.s, ok = n.openSession(m.PunchID, m.Addr); !ok {
			a.out.Status = wire.StatusFull
		}
	}
	a.weDial = a.ours == wire.ClassRandom
	a.theyRandom = m.Class == wire.ClassRandom
	if a.out.Status == wire.StatusOK && (a.weDial || a.theyRandom) {
		sockets := 0
		if a.weDial {
			sockets = punch.Sockets - 1
		}
		var ok bool
		if a.g, ok = n.budget.Burst(punch.Announcer, m.Addr.Addr(), sockets, now, from.Addr()); !ok {
			n.dropSession(a.s)
			a.out.Status = wire.StatusTryLater
		}
	}
	if a.out.Status != wire.StatusOK {
		return a
	}
	n.punching++
	if a.weDial {
		n.pending = append(n.pending, m.Addr.Addr())
	}
	a.w = n.watch(m.Key)
	return a
}

// punched answers a PUNCH with the MAC of a storer's punch secret and a counter it never took; anything else is
// dropped unanswered. An OK answer carries our signature and starts the punch.
func (n *Node) punched(id uint64, m *wire.Punch, from netip.AddrPort, size int) {
	a := n.admitPunch(m, from)
	if a == nil {
		return
	}
	out, ip, s, g, w, ours, weDial, theyRandom := a.out, a.ip, a.s, a.g, a.w, a.ours, a.weDial, a.theyRandom
	if out.Status != wire.StatusOK {
		n.reply(id, out, from, size)
		return
	}
	// The slot comes back when the probes end; a zero time frees it without starting RandomPunchInterval.
	var release sync.Once
	ended := func(end time.Time) {
		if g != nil {
			release.Do(func() { g.Done(end) })
		}
	}
	done := func(end time.Time) {
		n.unwatch(m.Key, w)
		n.closeSession(s)
		ended(end)
		n.mu.Lock()
		n.punching--
		if weDial {
			n.unreserve(m.Addr.Addr())
		}
		n.mu.Unlock()
	}
	sig, err := n.id.Sign(punchReplyContext, replySignable(m.PunchID, ours, ip))
	if err != nil {
		done(time.Time{})
		out.Status = wire.StatusRefused
		n.reply(id, out, from, size)
		return
	}
	out.Sig = [wire.SigSize]byte(sig)
	if !weDial {
		// The probe leaves before the answer, so our NAT is open toward the requester before it may dial.
		if !theyRandom {
			n.probe(s, m.Addr)
		}
		n.reply(id, out, from, size)
	}
	ok := n.spawn(func() {
		defer func() { done(time.Now()) }()
		wait := n.cfg.PunchTimeout
		if !weDial && !theyRandom {
			// The requester gives up a consistent pair after its probe window (connectVia), so we wait no longer.
			wait = min(wait, n.consistentWindow())
		}
		ctx, cancel := context.WithTimeout(n.ctx, wait)
		defer cancel()
		var bd *birthday
		stop := func() {}
		if weDial {
			// The relay waits only RequestTimeout: a slow open is answered OK at half of it, a failed one in time
			// try later, so the requester spends no window on a punch that never runs.
			var once sync.Once
			answer := func(st wire.Status) {
				once.Do(func() {
					if st != wire.StatusOK {
						out.Status, out.Sig = st, [wire.SigSize]byte{}
					}
					n.reply(id, out, from, size)
				})
			}
			slow := time.AfterFunc(n.cfg.RequestTimeout/2, func() { answer(wire.StatusOK) })
			var err error
			bd, err = n.openBirthday(s, m.Addr, g)
			slow.Stop()
			if err != nil {
				ended(time.Time{})
				answer(wire.StatusTryLater)
				return
			}
			defer bd.close()
			answer(wire.StatusOK)
			var ok bool
			if stop, ok = n.run(func(c <-chan struct{}) { bd.keepAlive(ctx, c); ended(time.Now()) }); !ok {
				return
			}
		} else if theyRandom {
			var ok bool
			if stop, ok = n.run(func(c <-chan struct{}) { n.randomProbes(ctx, c, s, m.Addr.Addr()); ended(time.Now()) }); !ok {
				return
			}
		}
		defer stop()
		// Only a connection from the probed /24 stops the cooldowns growing; anyone with the key can dial from elsewhere.
		var got netip.Addr
		select {
		case p := <-s.valid:
			stop()
			if weDial {
				if c, err := bd.dial(ctx, p, m.Key[:]); err == nil {
					n.mu.Lock()
					n.connected(c)
					n.mu.Unlock()
					// The node's own socket takes a proof from any sender of a probe with our punch id.
					if sameNet(c, m.Addr.Addr()) {
						g.Connected()
					}
					if p.holder > 0 {
						n.hold(c)
					}
					n.enqueue(c)
				}
				return
			}
			// Stay to answer late probes until the requester's connection arrives.
			select {
			case got = <-w:
			case <-ctx.Done():
				return
			}
		case got = <-w:
		case <-ctx.Done():
			return
		}
		if g != nil && addrs.Group(got) == addrs.Group(m.Addr.Addr()) {
			g.Connected()
		}
	})
	if !ok {
		done(time.Time{})
	}
}

// refuses reports whether our listener's AcceptFunc refuses connections from ap, so a punch for ap could never
// connect. A panic refuses, as in kolo-transport. It runs the caller's code, so call it without mu.
func (n *Node) refuses(ap netip.AddrPort) (refused bool) {
	tc, _ := n.cfg.transport()
	if tc.AcceptFunc == nil {
		return false
	}
	defer func() {
		if recover() != nil {
			refused = true
		}
	}()
	return !tc.AcceptFunc(ap)
}

// consistentWindow is how long a punch between two consistent mappings may take: the probes, then the dial.
func (n *Node) consistentWindow() time.Duration {
	return time.Duration(punch.ConsistentTries)*n.tm.consistentEvery + 2*n.cfg.RequestTimeout
}

// heldPerNet is how many held birthday connections one /24 may have: a home or CGNAT /24 keeps a few devices, and
// filling MaxPunches (16) takes 4 /24s.
const heldPerNet = 4

// canHold reports whether a birthday punch for ip fits: fewer than MaxPunches held or running, heldPerNet from its
// /24. Call with mu held.
func (n *Node) canHold(ip netip.Addr) bool {
	p := addrs.Group(ip)
	same := 0
	for _, x := range n.held {
		if addrs.Group(remoteIP(x)) == p {
			same++
		}
	}
	for _, x := range n.pending {
		if addrs.Group(x) == p {
			same++
		}
	}
	return len(n.held)+len(n.pending) < n.cfg.MaxPunches && same < heldPerNet
}

// unreserve drops one reservation of ip. Call with mu held.
func (n *Node) unreserve(ip netip.Addr) {
	if i := slices.Index(n.pending, ip); i >= 0 {
		n.pending = slices.Delete(n.pending, i, i+1)
	}
}

// hold keeps c, a live connection on a birthday socket of its own, until it closes. Its punch reserved the place, so
// a held connection is never closed for a new one.
func (n *Node) hold(c *kolosecure.Conn) {
	n.mu.Lock()
	n.held = append(n.held, c)
	n.mu.Unlock()
	drop := func() {
		n.mu.Lock()
		n.held = slices.DeleteFunc(n.held, func(x *kolosecure.Conn) bool { return x == c })
		n.mu.Unlock()
	}
	if !n.spawn(func() {
		select {
		case <-c.Context().Done():
		case <-n.ctx.Done():
		}
		drop()
	}) {
		drop()
	}
}

// sameNet reports whether c's peer sends from ip's /24; a NAT may use another address of its pool.
func sameNet(c *kolosecure.Conn, ip netip.Addr) bool {
	return addrs.Group(remoteIP(c)) == addrs.Group(ip)
}

func remoteIP(c *kolosecure.Conn) netip.Addr {
	ua, ok := c.RemoteAddr().(*net.UDPAddr)
	if !ok {
		return netip.Addr{}
	}
	return ua.AddrPort().Addr().Unmap()
}

// punchReplyContext is the Ed25519ctx context of an announcer's signature in an OK PUNCH reply.
const punchReplyContext = "kolo-dht/punch-reply/v1"

// replySignable is 0 ‖ punch id ‖ class ‖ the announcer's IPv4 address at the storer; the requester picks the
// punch id at random, so the signature is good for its punch only.
func replySignable(pid [wire.PunchIDSize]byte, class wire.Class, ip netip.Addr) []byte {
	a := ip.As4()
	return slices.Concat([]byte{0}, pid[:], []byte{byte(class)}, a[:])
}

// replayWindow is how many PUNCH counters of one storer above the floor a replay window remembers.
const replayWindow = 16

// replay takes each PUNCH counter of one storer once, in any order among the last replayWindow it took.
type replay struct {
	floor uint64
	taken [replayWindow]uint64 // 0 is free: a counter above floor is never 0
}

func (r *replay) take(c uint64) bool {
	if c <= r.floor || slices.Contains(r.taken[:], c) {
		return false
	}
	i := slices.Index(r.taken[:], 0)
	if i < 0 {
		i = slices.Index(r.taken[:], slices.Min(r.taken[:]))
		r.floor = r.taken[i]
		if c < r.floor {
			r.taken[i] = 0 // c is taken once but not stored: the floor never goes down
			return true
		}
	}
	r.taken[i] = c
	return true
}

func validMAC(secret [32]byte, m *wire.Punch) bool {
	mac, ok := punchMAC(secret, m)
	return ok && hmac.Equal(mac[:], m.MAC[:])
}

// Connect punches through up to 3 relays of r, PunchTimeout each, and returns a connection pinned to r.PublicKey. A
// relay that fails does not stop the next; only our own limits and the context do (the README lists the errors).
func (n *Node) Connect(ctx context.Context, r Record) (*kolosecure.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if n.ctx.Err() != nil {
		return nil, ErrClosed
	}
	if !addrs.IPv4(r.Addr) && r.Addr.Addr().IsValid() {
		return nil, errIPv6("record address")
	}
	if len(r.PublicKey) != wire.KeySize || samePublicKey(r.PublicKey, n.key) || len(r.relays) == 0 {
		return nil, fmt.Errorf("%w: record has no relay, or is our own", ErrInvalidArgument)
	}
	outer := ctx
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer context.AfterFunc(n.ctx, cancel)()
	last := ErrUnreachable
	punched := false
	for _, rl := range r.relays {
		actx, cancel := context.WithTimeout(ctx, n.cfg.PunchTimeout)
		c, err := n.connectVia(actx, r, rl)
		cancel()
		outerErr := ctxErr(outer)
		switch {
		case err == nil:
			return c, nil
		case n.ctx.Err() != nil:
			return nil, ErrClosed
		case outerErr != nil:
			return nil, outerErr
		case errors.Is(err, ErrTryLater), errors.Is(err, errBusy):
			// After a punch with the peer failed, a busy answer is that punch's cooldown, not a reason to retry.
			if punched {
				return nil, ErrUnreachable
			}
			return nil, ErrTryLater
		case errors.Is(err, errPeerBusy):
			last = ErrTryLater
		case errors.Is(err, errPunched):
			punched = true
		}
	}
	if punched {
		return nil, ErrUnreachable
	}
	return nil, last
}

// sendConnect asks the relay rl to have the peer of r punch toward us, and returns the peer's OK answer once its
// signature for this punch and IP verifies; any other answer is an error that says what Connect does next. busy is
// that our own budget would refuse the burst now.
func (n *Node) sendConnect(ctx context.Context, r Record, rl relay, pid [wire.PunchIDSize]byte, ours wire.Class, noRandom, busy bool) (*wire.ConnectReply, error) {
	tok := rl.token
	var cr *wire.ConnectReply
	for attempt := 0; ; attempt++ {
		req := &wire.Connect{Flags: n.flags(), Token: tok, Topic: [32]byte(r.Topic), Target: [wire.KeySize]byte(r.PublicKey), Key: n.key, Class: ours, NoRandom: noRandom, PunchID: pid}
		resp, err := n.request(ctx, rl.server, req, wire.MaxSize, 2*n.cfg.RequestTimeout)
		if err != nil {
			return nil, err
		}
		cr = resp.(*wire.ConnectReply)
		if cr.Status == wire.StatusBadToken && attempt == 0 {
			tok = cr.Token
			continue
		}
		break
	}
	switch cr.Status {
	case wire.StatusOK:
	case wire.StatusUnreachable:
		// Our own limit, not the peer's answer: try the next relay, and say try later only if none connects.
		if busy {
			return nil, errPeerBusy
		}
		return nil, errBothRand
	case wire.StatusTryLater, wire.StatusFull:
		return nil, errPeerBusy
	default:
		return nil, errRefused
	}
	// Only the peer can sign its OK for our punch and its IP at this relay, so a relay that lies is skipped at once.
	if !koloid.Verify(r.PublicKey, punchReplyContext, replySignable(pid, cr.Class, rl.addr.Addr()), cr.Sig[:]) {
		return nil, errRefused
	}
	return cr, nil
}

func (n *Node) connectVia(ctx context.Context, r Record, rl relay) (*kolosecure.Conn, error) {
	key := [wire.KeySize]byte(r.PublicKey)
	var pid [wire.PunchIDSize]byte
	rand.Read(pid[:])
	claim := make(chan *kolosecure.Conn, 1)
	n.mu.Lock()
	if _, busy := n.claims[key]; busy {
		n.mu.Unlock()
		return nil, errBusy
	}
	s, ok := n.openSession(pid, rl.addr)
	if !ok {
		n.mu.Unlock()
		return nil, errBusy
	}
	n.claims[key] = claim
	ours := n.nat.class(time.Now())
	n.mu.Unlock()
	defer n.closeSession(s)
	defer func() {
		n.mu.Lock()
		defer n.mu.Unlock()
		if n.claims[key] == claim {
			delete(n.claims, key)
		}
		// A connection the peer dialed meanwhile belongs to Accept.
		select {
		case c := <-claim:
			n.enqueue(c)
		default:
		}
	}()

	// The slot comes back when our probes end; a relay that fails before frees it without starting the interval.
	var g *punch.Grant
	var release sync.Once
	ended := func(end time.Time) {
		if g != nil {
			release.Do(func() { g.Done(end) })
		}
	}
	defer ended(time.Time{})
	won := func(c *kolosecure.Conn) (*kolosecure.Conn, error) {
		// A connection with the key from another network does not show the probes reached the peer.
		if g != nil && sameNet(c, rl.addr.Addr()) {
			g.Connected()
		}
		return c, nil
	}
	var bd *birthday
	if ours == wire.ClassRandom {
		// Our holders open before the CONNECT, so they exist when the peer's random probes start.
		if g, ok = n.budget.Acquire(punch.Connector, rl.addr.Addr(), punch.Sockets-1, time.Now()); !ok {
			return nil, ErrTryLater
		}
		var err error
		if bd, err = n.openBirthday(s, rl.addr, g); err != nil {
			return nil, err
		}
		defer bd.close()
	} else {
		// One probe before the CONNECT opens our NAT toward the peer before the relay asks it to probe us.
		n.probe(s, rl.addr)
	}
	// Without a confirmed IP, or when our budget would refuse the burst now, we will not probe random ports, so a
	// random peer must not open its sockets for us.
	busy := ours != wire.ClassRandom && rl.confirmed && n.budget.Refused(rl.addr.Addr(), time.Now())
	noRandom := ours != wire.ClassRandom && (!rl.confirmed || busy)
	cr, err := n.sendConnect(ctx, r, rl, pid, ours, noRandom, busy)
	if err != nil {
		return nil, err
	}
	theyDial := bd == nil && cr.Class == wire.ClassRandom
	var stop func()
	switch {
	case bd != nil:
		stop, ok = n.run(func(c <-chan struct{}) { bd.keepAlive(ctx, c); ended(time.Now()) })
	case theyDial:
		// Random-port probes go only to an IP that servers in two networks stored, never on one relay's word.
		if !rl.confirmed {
			return nil, errUnconfirmed
		}
		if g, ok = n.budget.Burst(punch.Connector, rl.addr.Addr(), 0, time.Now(), netip.Addr{}); !ok {
			return nil, ErrTryLater
		}
		stop, ok = n.run(func(c <-chan struct{}) { n.randomProbes(ctx, c, s, rl.addr.Addr()); ended(time.Now()) })
	default:
		stop, ok = n.run(func(c <-chan struct{}) {
			punch.Run(ctx, c, 0, n.tm.consistentEvery, punch.ConsistentTries-1, func(int) { n.probe(s, rl.addr) })
		})
	}
	if !ok {
		return nil, ErrClosed
	}
	defer stop()
	// Two consistent mappings meet within their probe window; past it this relay failed.
	var expired <-chan time.Time
	if bd == nil && !theyDial {
		t := time.NewTimer(n.consistentWindow())
		defer t.Stop()
		expired = t.C
	}
	for {
		select {
		case c := <-claim:
			return won(c)
		case p := <-s.valid:
			if theyDial {
				continue
			}
			stop()
			var c *kolosecure.Conn
			var err error
			if bd != nil {
				c, err = bd.dial(ctx, p, r.PublicKey)
			} else {
				c, err = n.sl.Dial(ctx, p.addr, r.PublicKey)
			}
			if err != nil {
				return nil, errPunched
			}
			if !bytes.Equal(c.RemotePublicKey(), r.PublicKey) {
				c.Close()
				return nil, errRefused
			}
			// A punch the peer asked of us meanwhile ends too: the peer's Connect takes c by its claim.
			n.mu.Lock()
			n.connected(c)
			n.mu.Unlock()
			return won(c)
		case <-expired:
			return nil, errPunched
		case <-ctx.Done():
			return nil, errPunched
		}
	}
}
