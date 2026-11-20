package kolodht

import (
	"bytes"
	"cmp"
	"context"
	"crypto/ed25519"
	"fmt"
	"net/netip"
	"slices"
	"sync"

	"github.com/ciranda-dev/kolo-dht/internal/addrs"
	"github.com/ciranda-dev/kolo-dht/internal/records"
	"github.com/ciranda-dev/kolo-dht/internal/table"
	"github.com/ciranda-dev/kolo-dht/internal/wire"
)

// answer is a server that replied during a lookup, with its reply.
type answer struct {
	addr  netip.AddrPort
	r     uint8
	id    table.ID
	reply wire.Message
}

type candidate struct {
	answer
	state int
}

const (
	fresh = iota
	asked
	answered
	silent
)

// Distance returns the Kademlia XOR distance between two 32-byte IDs, such as a topic and a node ID.
func Distance(a, b [32]byte) [32]byte { return table.Distance(a, b) }

// Closer reports whether a is closer to target than b by XOR distance, compared as big-endian unsigned integers.
func Closer(target, a, b [32]byte) bool {
	da, db := Distance(a, target), Distance(b, target)
	return bytes.Compare(da[:], db[:]) < 0
}

func distance(a, b table.ID) []byte {
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i]
	}
	return out
}

// lookup walks toward target, asking α servers at a time, and returns up to K servers that answered, closest first.
// With topic set it sends LOOKUP, otherwise FIND_NODE. It asks at most maxQueries servers.
func (n *Node) lookup(ctx context.Context, target table.ID, topic *Topic) ([]answer, error) {
	n.mu.Lock()
	seeds := n.table.Closest(target, table.K)
	self := n.selfID()
	n.mu.Unlock()
	if len(seeds) == 0 {
		return nil, ErrNoNodes
	}
	cands := map[table.ID]*candidate{}
	var order []*candidate
	add := func(addr netip.AddrPort, r uint8) {
		id := table.NodeID(addr.Addr(), r)
		n.mu.Lock()
		own := n.own(addr)
		n.mu.Unlock()
		if id == self || own || cands[id] != nil {
			return
		}
		c := &candidate{answer: answer{addr: addr, r: r, id: id}}
		cands[id] = c
		order = append(order, c)
	}
	for _, e := range seeds {
		add(e.Addr, e.R)
	}
	type result struct {
		c     *candidate
		reply wire.Message
		err   error
	}
	results := make(chan result)
	var wg sync.WaitGroup
	defer wg.Wait()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ask := func(c *candidate) {
		c.state = asked
		var m wire.Message = &wire.FindNode{Flags: n.flags(), Target: target}
		if topic != nil {
			m = &wire.Lookup{Flags: n.flags(), Topic: *topic}
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			reply, err := n.request(ctx, c.addr, m, wire.MaxSize, n.cfg.RequestTimeout)
			select {
			case results <- result{c, reply, err}:
			case <-ctx.Done():
			case <-n.ctx.Done():
			}
		}()
	}
	queries, inflight := 0, 0
	for {
		slices.SortFunc(order, func(a, b *candidate) int { return bytes.Compare(distance(a.id, target), distance(b.id, target)) })
		live := 0
		for _, c := range order {
			if live >= table.K || inflight >= alpha || queries >= maxQueries {
				break
			}
			switch c.state {
			case silent:
				continue
			case fresh:
				ask(c)
				queries++
				inflight++
			}
			live++
		}
		if inflight == 0 {
			break
		}
		select {
		case res := <-results:
			inflight--
			if res.err != nil {
				res.c.state = silent
				if ctxErr(ctx) == nil && n.ctx.Err() == nil {
					n.failed(res.c.addr, res.c.r)
				}
				continue
			}
			res.c.state = answered
			res.c.reply = res.reply
			var nodes []wire.Node
			switch m := res.reply.(type) {
			case *wire.FindNodeReply:
				nodes = m.Nodes
			case *wire.LookupReply:
				nodes = m.Nodes
			}
			for _, nd := range nodes {
				if nd.Flags.Server() && addrs.AllowedFrom(nd.Addr, res.c.addr.Addr()) {
					add(nd.Addr, nd.Flags.R())
				}
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-n.ctx.Done():
			return nil, ErrClosed
		}
	}
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	var out []answer
	for _, c := range order {
		if c.state == answered && len(out) < table.K {
			out = append(out, c.answer)
		}
	}
	if len(out) == 0 {
		return nil, ErrNoNodes
	}
	return out, nil
}

// Bootstrap pings servers, keeps those that answer and looks up our own ID: ErrNoNodes if none answered, and
// ErrInvalidArgument before sending anything if any address is IPv6, IPv4-mapped included.
//
// A nil servers list means PublicServers: the public entry nodes learn our IP and, once we Announce, store the topic
// and our address. To stay private pass your own servers; an empty list that is not nil is ErrInvalidArgument.
func (n *Node) Bootstrap(ctx context.Context, servers []netip.AddrPort) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if n.ctx.Err() != nil {
		return ErrClosed
	}
	if servers == nil {
		servers = publicServers
	}
	for _, s := range servers {
		if !addrs.IPv4(s) && s.Addr().IsValid() {
			return errIPv6("server address")
		}
	}
	var usable []netip.AddrPort
	ownOnly := false
	n.mu.Lock()
	for _, s := range servers {
		switch {
		case !addrs.Usable(s):
		case n.own(s):
			ownOnly = true
		case len(usable) < maxBoot && !slices.Contains(usable, s):
			usable = append(usable, s)
		}
	}
	n.mu.Unlock()
	switch {
	case len(usable) == 0 && ownOnly:
		return ErrNoNodes
	case len(usable) == 0:
		return fmt.Errorf("%w: no usable server address", ErrInvalidArgument)
	}
	n.mu.Lock()
	n.boot = usable
	n.mu.Unlock()
	var wg sync.WaitGroup
	ok := make(chan bool, len(usable))
	for _, s := range usable {
		wg.Add(1)
		go func() {
			defer wg.Done()
			reply, err := n.request(ctx, s, &wire.Ping{Flags: n.flags()}, pingSize, n.cfg.RequestTimeout)
			ok <- err == nil && reply.(*wire.PingReply).Flags.Server()
		}()
	}
	wg.Wait()
	close(ok)
	answered := false
	for v := range ok {
		answered = answered || v
	}
	if err := ctxErr(ctx); err != nil {
		return err
	}
	if n.ctx.Err() != nil {
		return ErrClosed
	}
	if !answered {
		return ErrNoNodes
	}
	n.mu.Lock()
	self := n.selfID()
	n.mu.Unlock()
	if _, err := n.lookup(ctx, self, nil); err != nil {
		if cerr := ctxErr(ctx); cerr != nil {
			return cerr
		}
		if n.ctx.Err() != nil {
			return ErrClosed
		}
	}
	return nil
}

// Lookup returns the records of topic stored at the servers closest to it, verified and merged by key, freshest first.
// Our own record is left out. It returns ErrNoNodes if no server answered.
func (n *Node) Lookup(ctx context.Context, topic Topic) ([]Record, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if n.ctx.Err() != nil {
		return nil, ErrClosed
	}
	answers, err := n.lookup(ctx, table.ID(topic), &topic)
	if err != nil {
		return nil, err
	}
	recs, _ := n.merge(topic, answers)
	return recs, nil
}

// merge verifies and merges the records of the K answers closest to topic by our own IDs. It checks at most maxVerify
// signatures, none past a server's first bad one, and returns the records and the checks made.
func (n *Node) merge(topic Topic, answers []answer) ([]Record, int) {
	target := table.ID(topic)
	answers = slices.Clone(answers)
	slices.SortStableFunc(answers, func(a, b answer) int { return bytes.Compare(distance(a.id, target), distance(b.id, target)) })
	answers = answers[:min(len(answers), table.K)]
	type seen struct {
		key  [wire.KeySize]byte
		addr netip.AddrPort
		sig  [wire.SigSize]byte
	}
	valid := map[seen]bool{}
	byKey := map[[wire.KeySize]byte]*Record{}
	var keys [][wire.KeySize]byte
	verified := 0
	for _, a := range answers {
		lr, ok := a.reply.(*wire.LookupReply)
		if !ok {
			continue
		}
		for _, wr := range lr.Records {
			if wr.Key == n.key || !addrs.AllowedFrom(wr.Addr, a.addr.Addr()) {
				continue
			}
			s := seen{wr.Key, wr.Addr, wr.Sig}
			ok, checked := valid[s]
			if !checked {
				if verified >= maxVerify {
					break
				}
				verified++
				ok = records.Verify(records.Record{Topic: topic, Key: wr.Key, Addr: wr.Addr, Sig: wr.Sig})
				valid[s] = ok
			}
			if !ok {
				break
			}
			rec := byKey[wr.Key]
			if rec == nil {
				rec = &Record{Topic: topic, PublicKey: ed25519.PublicKey(bytes.Clone(wr.Key[:]))}
				byKey[wr.Key] = rec
				keys = append(keys, wr.Key)
			}
			rec.relays = append(rec.relays, relay{server: a.addr, token: lr.Token, addr: wr.Addr, age: wr.Age})
		}
	}
	out := make([]Record, 0, len(keys))
	for _, k := range keys {
		rec := byKey[k]
		confirm(rec.relays)
		slices.SortStableFunc(rec.relays, func(a, b relay) int { return cmp.Compare(a.age, b.age) })
		rec.relays = rec.relays[:min(len(rec.relays), maxRelays)]
		rec.Addr = rec.relays[0].addr
		out = append(out, *rec)
	}
	slices.SortStableFunc(out, func(a, b Record) int { return cmp.Compare(a.relays[0].age, b.relays[0].age) })
	return out, verified
}

// confirm marks the relays whose peer IP servers in at least two networks, among the K closest, stored.
func confirm(rls []relay) {
	nets := map[netip.Addr]map[netip.AddrPort]bool{}
	for _, rl := range rls {
		ip := rl.addr.Addr()
		if nets[ip] == nil {
			nets[ip] = map[netip.AddrPort]bool{}
		}
		nets[ip][network(rl.server)] = true
	}
	for i := range rls {
		rls[i].confirmed = len(nets[rls[i].addr.Addr()]) >= 2
	}
}

// network is a server's /16; a server on loopback runs on this host and counts by its address, as in sampleKey.
func network(server netip.AddrPort) netip.AddrPort {
	if server.Addr().IsLoopback() {
		return server
	}
	return netip.AddrPortFrom(addrs.Wide(server.Addr()).Addr(), 0)
}
