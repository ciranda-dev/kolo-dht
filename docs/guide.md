# Guide

How to use kolo-dht beyond the README quick start. Every default and bound is in [limits.md](limits.md); the design, the wire format and references are in [protocol.md](protocol.md).

A real deployment runs a few servers (`Config.Server`) on public addresses, such as kolo-node, and peers bootstrap from them.

## NAT and address families

Nothing relays application data, and there is no automatic fallback: a pair of NATs that cannot be punched (both mappings random) gives `ErrUnreachable`, and an application can opt in to relays: kolo-swarm's `Config.Relays` lists kolo-relays and dials through them when `Connect` fails. kolo-dht is IPv4 only: IPv6 input is refused with `ErrInvalidArgument`, the IPv4-mapped form `::ffff:a.b.c.d` included, and a datagram from an IPv6 source is dropped.

## API

- `New(ctx, addr, id, cfg) (*Node, error)` opens one UDP socket on `addr`
  (such as `"127.0.0.1:0"` or `":4000"`) for the DHT and for kolo-secure
  connections as `id`. `Addr()` is its local address. `Close()` stops
  announcing, closes the socket and every connection of the node, and
  waits for its goroutines; it is safe to call more than once.
- `(*Node).Bootstrap(ctx, servers)` pings the given servers, keeps those
  that answer as servers, and looks up the node's own ID to fill its
  table. A nil `servers` joins the public network, by design, so an
  application works with no setup: it means `PublicServers()`, the built-in
  public entry nodes, which then see your IP address, and after `Announce`
  the public network stores your topic and address. A nil slice
  variable that was never appended to counts as nil. To stay private, pass
  your own servers; an empty list that is not nil is `ErrInvalidArgument`
  and sends nothing. The entry nodes have no key, so a client cannot check
  who answers at an address, and the addresses are compiled into each
  release.
  `ErrNoNodes` if none answered, `ErrInvalidArgument` if no address
  is usable. A server may skip it: it learns servers from those that query
  it.
- `PublicServers() []netip.AddrPort` returns a copy of that built-in list.
- `(*Node).Announce(ctx, topic)` stores a signed record of the node at the
  servers closest to `topic` and returns once one stored it
  (`ErrNotStored` if none did). It refreshes the record every 15s and
  repeats the lookup every 5 minutes, until `Unannounce(topic)` or
  `Close`; the servers drop a record 20 minutes after its last refresh.
  Announcing a topic again does nothing; past a `MaxAnnouncements` cap the
  application set it is `ErrInvalidArgument`; by default there is no cap.
- `(*Node).Lookup(ctx, topic) ([]Record, error)` returns the records of
  `topic` at the servers closest to it, each verified against its key and
  merged by key, freshest first, without the node's own record.
- `(*Node).Connect(ctx, record) (*kolosecure.Conn, error)` asks up to 3
  servers that returned the record, freshest first, to relay a connect
  request, punches, and returns a connection whose peer proved it holds
  `record.PublicKey`. Each relay gets at most `PunchTimeout`. It dials only
  an address that echoed its probe (see [protocol.md](protocol.md)), and runs at most 2
  attempts at once toward one destination host.
  `ErrUnreachable` if no relay led to a connection, also when the
  kolo-secure dial itself failed (its error is not returned), and when
  both sides have random NAT mappings, or the peer's is random and no two
  networks confirmed its IP (each relay answers at once). A relay's OK
  counts only with the peer's signature of it, so one lying relay is
  skipped at once and cannot end `Connect`.
  `ErrTryLater` at once, without counting against the peer, if this node
  already runs its 2 attempts toward the peer's host or a `Connect` to the
  same key. A relay that fails, whatever it answered, does not stop the
  next one; two consistent mappings give up on a relay after their probe
  window (10 probes 1s apart, plus 2 x `RequestTimeout`), and the peer
  stops waiting for the connection then. A peer whose listener refuses our
  address (`Secure.Transport.AcceptFunc`) answers refused, without a
  punch. `ErrTryLater` if a punch with a random mapping on one side is
  over a budget here, or if a relay said it was over the peer's, or
  answered that it or the peer was full, and no other relay connected.
  Once a relay ran a punch with the peer and it failed, `Connect` returns
  `ErrUnreachable`, also when a later relay is refused by that punch's
  cooldown.
- `(*Node).Accept(ctx) (*kolosecure.Conn, error)` returns the next inbound
  connection, punched or direct. Connections wait in a queue of
  `Secure.MaxPending` (64 by default); when it is full, new ones are closed
  with code 1. A `Connect` that waits for its peer to dial (see [protocol.md](protocol.md))
  takes that connection itself.
- `(*Node).Stats() Stats` returns `Servers` (routing table size), `Records`
  (records stored), and the counters `Requests` (requests that passed the
  rate limits) and `Limited` (requests they dropped) since `New`; take
  differences for rates. It is safe during traffic and after `Close`.
- `Topic` is a 32-byte value, such as a hash of a topic name. `Record` has
  `Topic`, `PublicKey` and `Addr` (the peer's address as the freshest
  server saw it), plus the servers to relay through. `Addrs()` returns
  every address `Connect` may probe or dial for it: `Addr` and the address
  each relay stored, once each, IPv4 only.
- `Distance(a, b) [32]byte` is the Kademlia XOR distance of two 32-byte
  IDs; `Closer(target, a, b) bool` reports whether `a` is closer to
  `target` than `b`.
- `Config.Trace func(TraceEvent)` sees each step of a punch: every probe
  sent (`TraceProbeSent`: local socket, remote address, size, TTL, 0 for
  the system default), every probe of our punches received
  (`TraceProbeReceived`), the sockets of a birthday punch
  (`TraceBirthdayOpened`, `Count` 256), the start of a random-port window
  (`TraceRandomProbes`, `Count` 1750) and an address that echoed our nonce
  (`TraceProved`). `TraceEvent.String` formats one log line, such as
  `Sending 35b to 203.0.113.7:37330 from port 49472 (TTL 5)`. It is called
  from the punch goroutines with no lock held, so it may call the node, and
  it must return fast. A random punch traces about 2000 probes on each side.
- Every blocking call returns `ctx.Err()` as soon as its context is done,
  and `ErrClosed` after `Close`. A deadline that has already passed counts
  as done even if the runtime has not yet marked the context (on a coarse
  timer, such as Windows or a busy VM, a request timeout can fire first), so
  the call returns `context.DeadlineExceeded`, not `ErrNoNodes` or
  `ErrUnreachable`.

## Errors

Errors, for `errors.Is`; none of them carries anything a peer sent:

- `ErrInvalidConfig`: a field is out of range. A kolo-secure or
  kolo-transport config error is wrapped, so its own sentinel matches too.
- `ErrInvalidArgument`, `ErrClosed`, `ErrNoNodes`, `ErrNotStored`,
  `ErrUnreachable` and `ErrTryLater` (see `Connect` above).
- kolo-secure and kolo-transport errors from opening the socket pass
  through.

