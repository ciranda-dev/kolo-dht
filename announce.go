package kolodht

import (
	"context"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/ciranda-dev/kolo-dht/internal/records"
	"github.com/ciranda-dev/kolo-dht/internal/table"
	"github.com/ciranda-dev/kolo-dht/internal/wire"
)

// storer holds our record of a topic: our token there, our address as it sees it, our X25519 key toward it (kept
// across refreshes), its share, the punch secret they agree and the PUNCH counters we took from it.
type storer struct {
	token    [wire.TokenSize]byte
	observed netip.AddrPort
	fails    int
	priv     *ecdh.PrivateKey
	share    [wire.ShareSize]byte
	secret   [32]byte
	replay   replay
}

// secretContext is the HKDF info prefix of punch secrets.
const secretContext = "kolo-dht/punch-secret/v1"

// punchSecret derives the punch secret of key's record for topic from our X25519 key and the other side's share
// peer. Both sides pass the announcer's share, then the storer's.
func punchSecret(priv *ecdh.PrivateKey, peer, announcer, storer [wire.ShareSize]byte, key [wire.KeySize]byte, topic [32]byte) ([32]byte, bool) {
	pub, err := ecdh.X25519().NewPublicKey(peer[:])
	if err != nil {
		return [32]byte{}, false
	}
	shared, err := priv.ECDH(pub) // refuses a low-order share
	if err != nil {
		return [32]byte{}, false
	}
	k, err := hkdf.Key(sha256.New, shared, nil, string(slices.Concat([]byte(secretContext), announcer[:], storer[:], key[:], topic[:])), 32)
	if err != nil {
		return [32]byte{}, false
	}
	return [32]byte(k), true
}

type announcement struct {
	topic   Topic
	ctx     context.Context
	cancel  context.CancelFunc
	storers map[netip.AddrPort]*storer
	sigs    map[netip.AddrPort][wire.SigSize]byte
}

// Announce stores a signed record of this node at the servers closest to topic and refreshes it until Unannounce
// or Close; it returns once one stored it (the README lists its errors). Announcing a topic again does nothing.
func (n *Node) Announce(ctx context.Context, topic Topic) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	n.mu.Lock()
	switch {
	case n.ctx.Err() != nil:
		n.mu.Unlock()
		return ErrClosed
	case n.announces[topic] != nil:
		n.mu.Unlock()
		return nil
	case len(n.announces) >= n.cfg.MaxAnnouncements:
		n.mu.Unlock()
		return fmt.Errorf("%w: MaxAnnouncements reached", ErrInvalidArgument)
	}
	actx, cancel := context.WithCancel(n.ctx)
	a := &announcement{topic: topic, ctx: actx, cancel: cancel, storers: map[netip.AddrPort]*storer{}, sigs: map[netip.AddrPort][wire.SigSize]byte{}}
	n.announces[topic] = a
	n.mu.Unlock()
	if err := n.announceRound(ctx, a); err != nil {
		n.mu.Lock()
		if n.announces[topic] == a {
			delete(n.announces, topic)
		}
		n.mu.Unlock()
		cancel()
		if cerr := ctxErr(ctx); cerr != nil {
			return cerr
		}
		if n.ctx.Err() != nil {
			return ErrClosed
		}
		return err
	}
	if !n.spawn(func() { n.refresher(a) }) {
		n.Unannounce(topic)
		return ErrClosed
	}
	return nil
}

// Unannounce stops refreshing the record of topic; the servers drop it within 20 minutes.
func (n *Node) Unannounce(topic Topic) {
	n.mu.Lock()
	a := n.announces[topic]
	delete(n.announces, topic)
	n.mu.Unlock()
	if a != nil {
		a.cancel()
	}
}

func (n *Node) announceRound(ctx context.Context, a *announcement) error {
	topic := a.topic
	answers, err := n.lookup(ctx, table.ID(topic), &topic)
	if err != nil {
		return err
	}
	n.mu.Lock()
	prev := make(map[netip.AddrPort]storer, len(a.storers))
	for addr, st := range a.storers {
		prev[addr] = *st
	}
	n.mu.Unlock()
	var mu sync.Mutex
	var wg sync.WaitGroup
	stored := map[netip.AddrPort]*storer{}
	for _, an := range answers {
		lr, ok := an.reply.(*wire.LookupReply)
		if !ok {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if st, ok := n.storeAt(ctx, a, an.addr, lr.Token, lr.Observed, prev[an.addr]); ok {
				mu.Lock()
				stored[an.addr] = st
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if len(stored) == 0 {
		return ErrNotStored
	}
	n.mu.Lock()
	for addr, st := range stored {
		if old := a.storers[addr]; old != nil && old.secret == st.secret {
			st.replay = old.replay
		}
	}
	a.storers = stored
	n.mu.Unlock()
	return nil
}

// storeAt sends ANNOUNCE to server, retrying once, signing only an address the samples trust, so one storer cannot
// make us sign a stranger's. It keeps prev's X25519 key, and its secret while the server's share stays the same.
func (n *Node) storeAt(ctx context.Context, a *announcement, server netip.AddrPort, tok [wire.TokenSize]byte, observed netip.AddrPort, prev storer) (*storer, bool) {
	priv := prev.priv
	if priv == nil {
		var err error
		if priv, err = ecdh.X25519().GenerateKey(rand.Reader); err != nil {
			return nil, false
		}
	}
	mine := [wire.ShareSize]byte(priv.PublicKey().Bytes())
	for attempt := 0; attempt < 2; attempt++ {
		n.mu.Lock()
		trusted := n.nat.trusted(observed, time.Now())
		n.mu.Unlock()
		if !trusted {
			return nil, false
		}
		sig, ok := n.sign(a, observed)
		if !ok {
			return nil, false
		}
		m := &wire.Announce{Flags: n.flags(), Token: tok, Topic: [32]byte(a.topic), Key: n.key, Addr: observed, Sig: sig, Share: mine}
		resp, err := n.request(ctx, server, m, 0, n.cfg.RequestTimeout)
		if err != nil {
			return nil, false
		}
		ar := resp.(*wire.AnnounceReply)
		switch {
		case ar.Status == wire.StatusOK:
			st := &storer{token: ar.Token, observed: ar.Observed, priv: priv, share: ar.Share, secret: prev.secret}
			if prev.priv != priv || prev.share != ar.Share {
				if st.secret, ok = punchSecret(priv, ar.Share, mine, ar.Share, n.key, [32]byte(a.topic)); !ok {
					return nil, false
				}
			}
			return st, true
		case ar.Status == wire.StatusBadToken || (ar.Status == wire.StatusRefused && ar.Observed != observed):
			tok, observed = ar.Token, ar.Observed
		default:
			return nil, false
		}
	}
	return nil, false
}

// sign returns our signature for the topic at addr, made once per address.
func (n *Node) sign(a *announcement, addr netip.AddrPort) ([wire.SigSize]byte, bool) {
	n.mu.Lock()
	sig, ok := a.sigs[addr]
	n.mu.Unlock()
	if ok {
		return sig, true
	}
	r, err := records.Sign(n.id, [32]byte(a.topic), addr)
	if err != nil {
		return sig, false
	}
	n.mu.Lock()
	if len(a.sigs) >= maxSamples {
		clear(a.sigs)
	}
	a.sigs[addr] = r.Sig
	n.mu.Unlock()
	return r.Sig, true
}

func (n *Node) refresher(a *announcement) {
	refresh := time.NewTicker(n.tm.refresh)
	defer refresh.Stop()
	relookup := time.NewTicker(n.tm.relookup)
	defer relookup.Stop()
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-refresh.C:
			n.refreshAll(a)
		case <-relookup.C:
			n.announceRound(a.ctx, a)
		}
	}
}

// refreshAll re-sends ANNOUNCE to every storer; one that fails twice in a row is dropped until the next lookup.
func (n *Node) refreshAll(a *announcement) {
	n.mu.Lock()
	type job struct {
		addr netip.AddrPort
		st   storer
	}
	var jobs []job
	for addr, st := range a.storers {
		jobs = append(jobs, job{addr, *st})
	}
	n.mu.Unlock()
	var wg sync.WaitGroup
	for _, j := range jobs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			st, ok := n.storeAt(a.ctx, a, j.addr, j.st.token, j.st.observed, j.st)
			if a.ctx.Err() != nil {
				return
			}
			n.mu.Lock()
			defer n.mu.Unlock()
			cur := a.storers[j.addr]
			switch {
			case cur == nil:
			case ok:
				if cur.secret == st.secret {
					st.replay = cur.replay
				}
				*cur = *st
			default:
				if cur.fails++; cur.fails >= 2 {
					delete(a.storers, j.addr)
				}
			}
		}()
	}
	wg.Wait()
}
