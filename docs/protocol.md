# Protocol and design

## Design

- One socket for QUIC and the DHT: hole punching only works if the address
  other nodes see for us is the NAT mapping of the QUIC listener's socket.
  DHT requests are datagrams, not QUIC connections, because a lookup asks
  20 to 60 servers and a connection to each would cost several round trips
  and a handshake.
- Every datagram is at most 1200 bytes, and starts with the byte 0x24, whose
  two top bits are clear, so QUIC never parses it.
- A reply is never longer than the request that caused it: requests carry
  zero padding up to the reply size they want back, and list replies drop
  records, then nodes, to fit. A server relays a connect request only for a
  request padded to 1200 bytes, so the relayed request and the probes that
  follow stay below it.
- Round-trip tokens: every reply carries an HMAC-SHA256 token of the
  requester's IP and port, with a secret that changes every 40s (a token is
  accepted for 40 to 80s). ANNOUNCE and CONNECT need a valid token, so
  nothing is stored or relayed for an address that has not received a
  packet from the server. A request with an expired token gets a bad-token
  reply with a fresh token and is sent once more. The lifetime comes from a
  measurement at default settings, of the time between the reply that gave
  a token and the request that used it, over 6 minutes: in the simulator
  (40 servers, 12 peers behind NATs, 20ms latency) the longest was 0.12s
  for an ANNOUNCE after its lookup, 15.04s for a refresh and 10.09s for a
  CONNECT to the third relay; with 2% loss 14.8s, 31s (a refresh after a
  lost reply) and 11.1s; on loopback (30 servers, 10 peers) 1.0s, 15.0s
  and 0.01s.
- A reply counts only if its 8-byte random id, its type and its exact source
  address match a request in flight.
- Servers and clients (`Config.Server`): only servers answer queries, store
  records and enter routing tables, and only after they answered a request
  sent to their address.
- Node IDs are SHA-256 of a context, the IPv4 address, and a
  choice r from 0 to 7, so one address has at most 8 IDs, at positions it
  cannot choose. Messages carry r, and the receiver
  computes the ID from the address it sees. A server that sees another
  server on its own IP with its r, in a reply to its own request, picks
  another r (at most once a minute), so up to 8 servers can share an IP; an
  address holds one table entry. A request of our own that reaches our own
  socket, and our own address in a `Bootstrap` list, are ignored.
- A server that sends us a request with the server flag gets a ping back
  before it may enter the table, only if the request left room for that
  ping beside its reply (so the two together never exceed the request), and
  at most 4 per second toward one /24.
- Routing table: 256 buckets of 20, at most 2 entries per IPv4 /24 in a
  bucket and 10 in the table, a limit against eclipse attacks (see the
  eclipse papers in the references). A full bucket keeps its oldest entry
  unless it has been silent for 15 minutes and then fails a ping (Kademlia).
- Records are signed with Ed25519ctx under the context
  `kolo-dht/announce/v1` over the topic, the key and the announcer's
  address as the storing server sees it, so a record cannot be moved to
  another address; kolo-id rejects small-order keys. A server stores a
  record only from that address, and when full it refuses new records and
  never evicts live ones; one IPv4 /24 holds at most a sixteenth of the
  records of a topic. Records are stored at the 20 servers closest to
  the topic and live 20 minutes after their last refresh.
- Incoming requests are counted per IPv4 address, per /24 and in total,
  in 1-second windows, before they are decoded. An ANNOUNCE that needs a
  key agreement or a signature check (a new record, address, signature or
  share, not a plain refresh) is also counted against a smaller budget of its
  own, and has no reply past it; both checks run without the node lock.
- An address learned from another node is used only if it is global or in
  the same scope (loopback, link-local, private) as that node, so a public
  node cannot point us into our own network. The documentation ranges
  (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), 192.0.0.0/24 and the
  benchmarking range 198.18.0.0/15 count as global, because the simulator
  and the tests use them as public addresses; they are not routable on the
  Internet, so a server that hands them out only makes a client send probes
  that go nowhere, within the punch limits.
- Hole punching, coordinated by a server that holds the announcer's record
  (its refreshes keep the announcer's NAT open toward it). The connecting
  peer sends one probe to the record's address, then CONNECT to the
  server, which forwards a PUNCH to the announcer. At ANNOUNCE the
  announcer and the server agree a punch secret for the record (X25519
  shares in ANNOUNCE and its reply, then HKDF-SHA256 with the context
  `kolo-dht/punch-secret/v1`); every PUNCH carries the server's next
  counter and an HMAC-SHA256 under that secret (context
  `kolo-dht/punch/v1`). The announcer drops, without an answer, a PUNCH
  whose MAC is missing or wrong or whose counter it already took from that
  server (it remembers the last 16, so reordering is accepted), so a
  spoofed source makes it send nothing. Its OK answer carries its
  signature of the punch id (random, chosen by the requester), its class
  and its IP as that server saw it (context `kolo-dht/punch-reply/v1`); the connector
  acts on an OK only with that signature for the IP it would probe, so a
  relay that lies, or replays a record of a peer that has moved, is
  skipped at once and starts no burst. The announcer sends one
  probe toward the address the PUNCH names, smaller than the PUNCH, before
  it answers, so its NAT is open before the other side dials. Each probe
  carries a random nonce, and a peer answers a probe that carries one with
  its own nonce and the echo, in a datagram of the same size, at most 4
  times. An address is proved once it echoes our nonce from an address we
  sent it to; nothing else goes to an address before that, and only a
  proved address is dialed. So a lying server, or a record that names a
  stranger, makes us send at most one probe (at the announcer) or ten
  (at the connector) and never a QUIC packet. The side whose NAT mapping
  changes with the destination dials; the other only probes. If both
  mappings change, each relay answers at once and `Connect` fails. A peer that probes us gets our
  nonce in the answer, so its echo proves only its own real address.
- One random mapping: the birthday technique. The random side opens 255
  sockets beside its own, and each sends one probe with TTL 5 to the peer's
  address: it opens a mapping in our NAT and dies before the peer's. The consistent side sends a
  probe to a random port (1000 to 65535) of the random side's IP every
  20 ms, 1750 times (35 s). One lands on an open mapping with
  probability 1 - (1 - 255/64536)^1750, about 0.999. The socket that gets
  the echo of its probe dials the peer; the others close at once, and the
  winner gets its own listener until its connection ends (it leaves the
  socket budget once the connection is up). The sockets
  renew their mappings every 5 s during the window, at TTL 5 until the
  peer has reached one of them. Both sides send only to the address the
  storing server proved by a round trip (its token for the connector; the
  record's address, stored after a token round trip, for the announcer):
  random ports of that IP, or that exact address. The connector probes
  random ports only of an IP that servers in two /16s, among the K closest
  answers to its own lookup, stored the record at, so one lying server
  cannot aim them; a random peer shows each server another port, so the
  IP is what they agree on. Without that, its CONNECT says it will not
  probe random ports, and a random peer answers unreachable before it
  opens anything. Two colluding servers can still aim one window at an IP
  of their choice (see the limits at the end of this section). A storer
  the announcer chose can still name a wrong requester
  IP, which gets at most one window of 35-byte probes; `MaxRandomPunches`,
  the per-host limits, `RandomPunchInterval`, `RandomPunchCooldown` (per
  IP, and per /24 and per storer at the announcer, from the end of a
  burst, growing up to 16 times as long while bursts connect nothing from
  the probed /24) and
  `MaxRandomPunchesPerMinute` bound how often. Named as a consistent requester to
  a random announcer, a wrong address gets one probe at the default TTL and
  255 at TTL 5, which reach only hosts within 4 hops.
- NAT mapping class, learned passively from the addresses servers report
  in their replies to our own PING, FIND_NODE and LOOKUP requests (it sends
  nothing of its own):

  | Rule | Value |
  |---|---|
  | Window | the last 16 samples, one per server /24 (a loopback server, on this host and behind no NAT, counts by address and port) |
  | Minimum | 3 live samples; with fewer the class is unknown, which behaves as consistent |
  | Consistent | more than half of the samples report one address |
  | Random | otherwise |
  | Age | a sample expires 30 minutes after it was taken |
  | Clear | when another address than the last majority gains a majority (a network change), the samples that disagree with it are dropped |
  | Signed address | the majority address; below 3 samples, an address a server reported; with a random mapping, one whose IP more than half of the samples report |

  One lying server cannot make the class random: below 3 samples there is
  no class, and from 3 on the honest samples keep their majority. Two
  lying servers in two /24s can when the window holds at most 4 samples
  (two honest ones); then no IP has a majority either, so nothing is
  signed until more servers reply. That costs only the node its own
  connections. A fresh node whose only server lies can still sign a wrong
  address, which makes it unreachable but sends nothing to that address
  that it has not proved. Unknown behaves as consistent, and the socket is
  never reopened to sample again: it is the one socket shared with QUIC,
  whose NAT mapping is the address peers dial, so a new socket would lose
  the announced address and every open connection. The age comes from a
  simulator measurement at default settings, over 36 minutes: an idle node
  gets its replies from the routing-table pings, 5 every 40s, each server
  again after 15 minutes of silence and the next tick. With 8 servers a
  sample was replaced every 16 minutes, and with 20 servers the oldest live
  sample was 17 minutes 19s old; the window never lost a sample and the
  class was never unknown. An announcing node also gets about 20 samples
  every 5 minutes from its lookups, so its oldest sample was 5 minutes old.
  After a network change the old samples are dropped as soon as the new
  address has a majority (9 of 16 new samples). With 20 servers that took
  3 minutes for an announcing node (its next lookup) and 14 minutes for
  an idle one (40s into its next ping burst), and it takes at most 30
  minutes in any case.
- What v0.1.x punches, checked end to end over the in-process NAT
  simulator (`internal/netsim`, RFC 4787 behaviors, with addresses from the
  RFC 2544 benchmarking range 198.18.0.0/15 and the documentation ranges)
  and not on real NATs. Consistent: public, full cone (EIM, EIF),
  restricted (EIM, ADF) and port restricted (EIM, APDF); random: symmetric
  (APDM) and address-dependent mapping (ADM).

  Connects that succeeded, out of attempts, over 20 simulator seeds for
  each pair of the six kinds (5ms latency, punch intervals shortened to
  1ms, 3s `PunchTimeout`, three servers in two /16s), plus 200 more seeds
  for each of the four port restricted and random pairs, measured again
  after PUNCH authentication and the two-network check of random-port
  probes:

  | Connector \ announcer | public, full cone, restricted | port restricted | random |
  |---|---|---|---|
  | public, full cone, restricted | 180/180 | 60/60 | 120/120 |
  | port restricted | 60/60 | 20/20 | 440/440 (birthday) |
  | random | 120/120 | 438/440 (birthday) | 0/80, `ErrUnreachable` at once |

  At the default intervals (20ms random probes, 1s consistent probes, 45s
  `PunchTimeout`), the four birthday pairs connected 239 of 240 times over
  three runs of 80, in 4 to 6s on average from `Announce`. A birthday punch
  that finds no open mapping in its window fails like any other punch,
  near the analytic 1 in 1000: 7 of 6600 birthday connects at 1ms
  intervals missed (1 of 2640 before these changes). The birthday punch is
  proven only in this simulator, whose NATs pick a random port from 1024 to 65535 for each
  new mapping and drop a packet whose TTL runs out on the 8 routers
  between two NATs; real NATs that allocate ports another way, cap
  mappings per host or rate limit new ones may do worse. The analytic
  rate is about 0.999 (above).

  Two random mappings still fail at once with `ErrUnreachable`. There is
  no automatic fallback: an application that needs those pairs can opt in
  to relays: kolo-swarm's `Config.Relays` lists kolo-relays and dials
  through them when `Connect` fails. Two peers behind one NAT connect only
  if it hairpins.
- At most 160 signatures are checked per `Lookup`, and a server's records
  stop being checked at its first bad signature.
- kolo-dht relays no data: a pair that cannot be punched gets
  `ErrUnreachable`, and kolo-swarm's `Config.Relays` can dial through
  kolo-relays then.
- Random-port probes start only when two storers in different /16 prefixes
  confirm the peer's IP, so on a network whose servers share one /16, a
  `Connect` from a consistent mapping to a random one returns
  `ErrUnreachable` at once, and the peer opens no socket for it.
- Not closed, by design: two colluding servers in two /16s, both among
  the K closest answers for a topic, can serve a record they signed
  themselves and make each connector that calls `Connect` on it send one
  window of random-port probes (1750 probes, 61 KB) to an IP they choose.
  That is at most about 1.1 KB/s per connector over all IPs and about
  60 B/s toward one IP, and it grows linearly with the number of
  connectors. Getting a server among the K closest takes about N/160 IPs
  per /16 on a network of N servers; on a network of 20 servers or fewer
  every server qualifies. A random-mapped peer cannot prove its IP before
  the window.
- Not closed, by design: attackers that complete real punches can keep
  an announcer's one random punch at a time from 3 /24s, because the
  default 20s `RandomPunchInterval` allows 3 random punches a minute.
  When a peer stays unreachable, for this or any other reason,
  kolo-swarm's `Config.Relays` dials through kolo-relays.
- Not closed: when a peer's PUNCH reaches us only after our own `Connect`
  to it has connected, and the peer's `Connect` takes that connection, the
  punch we answer waits for a connection the peer will not make. It ends
  with the probe window of two consistent mappings (12s by default, 45s
  `PunchTimeout` with a random mapping) and holds one of the 2 places
  toward that host meanwhile. Telling us that the punch is over would take
  a new message.
- Not closed, by design: a connection from the probed /24 counts as a
  successful burst, so a NAT that sends from another address of its pool
  backs off normally. An attacker with a host in the victim's /24 can then
  raise the probes toward that IP from about 60 B/s to about 1 KB/s.
- Not closed, by design: an announcer with a random mapping keeps at most
  `MaxPunches` (16) connections on birthday sockets of their own, 4 per
  /24 so a home or CGNAT /24 keeps a few devices, and never closes one for
  a new one. When they are full it answers a new random punch with try
  later, so attackers that keep connections from 4 /24s block new
  birthday punches to it for as long as they hold them; peers already
  connected stay connected.
- Not guaranteed: finding every peer of a topic (servers can be offline,
  full or lying), resistance to an attacker with many /24 prefixes
  (Sybil), privacy of topics and addresses (DHT traffic is not encrypted),
  and reaching an announcer behind a NAT that drops mappings in under 15s.

## Formats

Every datagram, in [kolo-codec](https://github.com/ciranda-dev/kolo-codec)
encoding:

    0x24 ‖ uvarint(type) ‖ uint64(request id) ‖ body ‖ bytes(zero padding)

An address is `IPv4 address (4 bytes) ‖ uvarint(port, 1 to 65535)`. A node is
`uvarint(flags) ‖ address`, with r in bits 0 to 2 and the server flag in
bit 3. Status, class and no-random (0 or 1) are uvarints.

| Type | Name | Body |
|---|---|---|
| 1 | PING | flags |
| 2 | PING reply | observed address ‖ token (32) ‖ flags |
| 3 | FIND_NODE | flags ‖ target (32) |
| 4 | FIND_NODE reply | observed address ‖ token ‖ flags ‖ uvarint(n ≤ 20) ‖ n nodes |
| 5 | LOOKUP | flags ‖ topic (32) |
| 6 | LOOKUP reply | as 4, then uvarint(m ≤ 16) ‖ m × (key (32) ‖ address ‖ uvarint(age in s) ‖ signature (64)) |
| 7 | ANNOUNCE | flags ‖ token ‖ topic ‖ key ‖ address ‖ signature ‖ X25519 share (32) |
| 8 | ANNOUNCE reply | observed address ‖ token ‖ status ‖ X25519 share (32) |
| 9 | CONNECT | flags ‖ token ‖ topic ‖ target key ‖ own key ‖ class ‖ no-random ‖ punch id (8) |
| 10 | CONNECT reply | observed address ‖ token ‖ status ‖ class ‖ signature (64, zero unless ok) |
| 11 | PUNCH | flags ‖ topic ‖ target key ‖ requester key ‖ requester address ‖ class ‖ no-random ‖ punch id ‖ uint64(counter) ‖ MAC (32) |
| 12 | PUNCH reply | status ‖ class ‖ signature (64, zero unless ok) |
| 13 | PROBE | punch id ‖ nonce (8) ‖ echo (8) |

Status: 0 ok, 1 bad token, 2 full, 3 not a server, 4 no such record, 5
unreachable, 6 refused, 7 try later. Class: 0 unknown, 1 consistent mapping, 2 random
mapping.

Signed announcement: `uvarint(0) ‖ topic ‖ key ‖ address`. Node ID:
`SHA-256("kolo-dht/node-id/v1" ‖ IPv4 address (4 bytes) ‖ r)`. Token: `HMAC-SHA256(secret, 4-byte IPv4 address ‖ 2-byte big-endian port)`.
Punch secret: `HKDF-SHA256(X25519(own key, other share), info = "kolo-dht/punch-secret/v1" ‖ announcer share ‖ server share ‖ announcer key ‖ topic)`.
PUNCH MAC: `HMAC-SHA256(punch secret, "kolo-dht/punch/v1" ‖ the PUNCH datagram with request id 0 and a zero MAC)`.
PUNCH reply signature: Ed25519ctx by the announcer's key, context `kolo-dht/punch-reply/v1`, over
`0 ‖ punch id ‖ class (1 byte) ‖ announcer's IPv4 address at that server (4 bytes)`; the requester picks the punch id at random.
There is no JSON form.

## References

- Maymounkov and Mazieres, [Kademlia](https://doi.org/10.1007/3-540-45748-8_5), IPTPS 2002.
  Takes: the XOR metric, k-buckets, iterative lookup.
- Baumgart and Mies, [S/Kademlia](https://doi.org/10.1109/ICPADS.2007.4447808), ICPADS 2007.
  Takes: IDs a node cannot choose freely.
  Not implemented: crypto puzzles.
- [RFC 4787, NAT Behavioral Requirements for Unicast UDP](https://www.rfc-editor.org/info/rfc4787) (BCP, February 2007).
  Takes: the NAT behavior classes, used by the simulator.
- [RFC 5128, State of P2P Communication across NATs](https://www.rfc-editor.org/info/rfc5128) (Informational, March 2008).
  Takes: UDP hole punching.
- Ford, Srisuresh and Kegel, [Peer-to-Peer Communication Across Network Address Translators](https://bford.info/pub/net/p2pnat/), USENIX ATC 2005.
  Takes: UDP hole punching.
- [RFC 8489, Session Traversal Utilities for NAT (STUN)](https://www.rfc-editor.org/info/rfc8489) (Proposed Standard, February 2020).
  Takes: the idea of learning the address a peer is seen from.
  Not implemented: STUN messages.
- [RFC 8445, ICE: A Protocol for NAT Traversal](https://www.rfc-editor.org/info/rfc8445) (Proposed Standard, July 2018).
  Not implemented: ICE itself.
- [RFC 9000, QUIC: A UDP-Based Multiplexed and Secure Transport](https://www.rfc-editor.org/info/rfc9000) (Proposed Standard, May 2021) and [RFC 9443, Multiplexing Scheme Updates for QUIC](https://www.rfc-editor.org/info/rfc9443) (Proposed Standard, July 2023).
  Takes: one socket for QUIC and the DHT, told apart by the first byte (0x24 with the top bits clear).
- [RFC 8032, Edwards-Curve Digital Signature Algorithm (EdDSA)](https://www.rfc-editor.org/info/rfc8032) (Informational, January 2017).
  Takes: Ed25519ctx for the signed records.
- [RFC 7748, Elliptic Curves for Security](https://www.rfc-editor.org/info/rfc7748) (Informational, January 2016).
  Takes: X25519 for the punch secret.
- [RFC 5869, HMAC-based Extract-and-Expand Key Derivation Function (HKDF)](https://www.rfc-editor.org/info/rfc5869) (Informational, May 2010).
  Takes: the punch secret derivation.
- [RFC 2104, HMAC: Keyed-Hashing for Message Authentication](https://www.rfc-editor.org/info/rfc2104) (Informational, February 1997).
  Takes: the PUNCH datagram authentication.
- Douceur, [The Sybil Attack](https://doi.org/10.1007/3-540-45748-8_24), IPTPS 2002.
  Takes: the threat model.
- Heilman, Kendler, Zohar and Goldberg, [Eclipse Attacks on Bitcoin's Peer-to-Peer Network](https://www.usenix.org/conference/usenixsecurity15/technical-sessions/presentation/heilman), USENIX Security 2015.
  Takes: per-bucket and per-table address limits.
- Marcus, Heilman and Goldberg, [Low-Resource Eclipse Attacks on Ethereum's Peer-to-Peer Network](https://eprint.iacr.org/2018/236), IACR ePrint 2018/236.
  Takes: per-bucket and per-table address limits.
