# Limits

Every option, default and bound of kolo-dht, with the reason for it. Fixed limits are marked fixed.

## Config

`Config` (nil or a zero field means the default; out of range is
`ErrInvalidConfig`). Every limit, configurable or fixed, is below. Fixed
limits are marked fixed.

| Option | Default | Range | Why |
|---|---|---|---|
| `Secure` (passed to kolo-secure; `Secure.Transport` to kolo-transport) | their defaults, but a zero `KeepAlivePeriod` becomes 5s unless `IdleTimeout` is 5s or less | see kolo-secure and kolo-transport | Keeps the NAT mappings of punched connections open with keep-alives every 5s. |
| `Server` (answer queries, store records, relay connect requests) | false | | Only servers answer queries, store records and enter routing tables (see [protocol.md](protocol.md)). |
| `MaxRecords` (stored, all topics) | 65536 | 16 to 1,000,000 | Bounds the memory of the store. A record takes up to about 710 heap bytes (measured on 64-bit by `TestHeapPerRecord`, one record per topic, address and /24), so a full store takes `MaxRecords` x 710 bytes, 44 MiB at the default; count it in `GOMEMLIMIT`. |
| `MaxRecordsPerTopic` | 512, of which at most a sixteenth (32) from one IPv4 /24 | 1 to 65536 | Bounds how few networks can fill a topic. Scaled with `MaxRecords` (x16), so 512 announcers of one topic fit. A server never evicts a live record, so without the /24 share two addresses could hold a topic for as long as they refresh; with it, filling a topic takes 16 /24s, and up to 32 peers behind one network still share a topic. |
| `MaxRecordsPerIP` (per announcing IPv4 address, all topics) | 256 | 1 to 65536 | Bounds the records of one address: filling a store takes 256 IPv4 addresses (x16 with `MaxRecords`); 16 hosts behind one address, each announcing 16 topics at one server, fit. One address holds at most 32 records of one topic (the /24 share above). |
| `MaxAnnouncements` (topics this node announces) | 16 | 1 to 256 | Bounds this node's refresh traffic: 16 topics to 20 servers every 15s is 21 datagrams a second. kolo-swarm raises it to its `MaxTopics`. |
| `MaxInflight` (requests waiting for a reply) | 160 | 8 to 4096 | Bounds the requests in flight. 16 announcements looking up at once at concurrency 10 fill it: other requests (refreshes, maintenance pings) then wait for a slot, and the optional check pings of new servers are skipped until a slot is free. |
| `MaxRelays` (connect requests a server relays at once) | 64 | 1 to 4096 | Bounds the PUNCH requests a server sends for others. |
| `MaxPunches` (punch requests answered at once) | 16 | 1 to 256 | Bounds the punch sessions and probes of an announcer. A punch with a random mapping also counts against `MaxRandomPunches`. It also bounds the connections punches made on birthday sockets of their own, 4 per /24: past that a new random punch is answered try later and an established one is never closed, so they bound file descriptors. |
| `MaxRequestsPerIP` (per second, per IPv4 address) | 50 | 1 to 10,000 | Bounds one address, and fits its own refreshes (one per record every 15s): 256 records refreshed from one address take 17 a second. |
| `MaxRequestsPerPrefix` (per second, per IPv4 /24) | 200 | `MaxRequestsPerIP` to 100,000 | Bounds a Sybil with one /24. |
| `MaxRequests` (per second, total) | 10,000 | `MaxRequestsPerPrefix` to 1,000,000 | Fits a full store: its refreshes alone are 65536 / 15s = 4369 a second, plus 218 a second of 5-minute lookups; the old 2000 did not fit them. A reply is never larger than its request. |
| `RequestTimeout` | 1s | 100ms to 10s | Bounds the wait for the reply to one datagram; an entry is dropped only after 4 failed requests in a row. |
| `PunchTimeout` (per relay, a 35s random punch and its handshake included) | 45s | 1s to 2m | Covers the 35s random window plus the kolo-secure handshake. Two consistent mappings give up on a relay after 12s, and the announcer stops waiting for the connection then, so one lying relay cannot hold `Connect` for 45s; after a random punch the budget refuses another for a while. |
| `MaxRandomPunches` (punches with a random mapping on one side, both roles) | 1 | 1 to 16 | One such punch holds 255 sockets or sends up to 1750 probes, so one at a time bounds what a node holds and sends. |
| `MaxRandomPunchesPerTarget` (connector, per peer IPv4 address) | 1 | 1 to `MaxRandomPunches` | With a higher `MaxRandomPunches`, still one punch toward one peer address. |
| `MaxRandomPunchesPerRequester` (announcer, per requester IPv4 address) | 1 | 1 to `MaxRandomPunches` | As above, for the address a storer names: one requester address gets at most one window of probes at a time. |
| `RandomPunchInterval` (from the end of one random punch to the next) | 20s (`DefaultRandomPunchInterval`) | 1s to 10m | Bounds how often random punches run: 3 a minute at the default. A relay that fails before the peer agreed does not start it, so failover to the next relay still works. |
| `RandomPunchCooldown` (between two bursts toward one IPv4 address, or started by one storer's PUNCH) | 1m | 1s to 1h | An unauthenticated PUNCH or an unconfirmed relay claim could be used to aim probes at a third party. Counted from the end of the last burst, per IP, per /24 at the announcer and per storer; for an IP or /24 it doubles after each burst that made no connection from the probed /24, up to 16 times as long (16 minutes). So requesters that alternate cannot keep the announcer's one random punch (`TestBurstSlotMonopoly`), and one storer cannot aim bursts at IP after IP. |
| `MaxRandomPunchesPerMinute` (bursts started in any minute, both roles) | 4 | 1 to 64 | The same reason as `RandomPunchCooldown`. Bounds the bursts when `MaxRandomPunches` is raised: at the default each is a window of up to 1750 probes of 35 bytes, so at most about 245 KB a minute leave toward random ports. |
| `MaxPunchSockets` (sockets running punches hold besides the node's own) | 256, or half the soft `RLIMIT_NOFILE` if less | 1 to 16384 | A birthday punch needs 255; below that it always answers try later. Half the file descriptor limit stays for kolo-transport and the application. The winning socket leaves the count once its connection is up or failed, so live connections do not hold the budget; at the announcer `MaxPunches` bounds them instead. |
| `Trace` (callback for every punch probe and step) | nil | | Debugging and demos: shows the probes and the birthday punch, which the API otherwise hides. Off by default, since a random punch makes about 2000 calls on each side. |
| Bucket size and replication k | 20 | fixed | Sets the table (256 buckets of 20) and the 20 servers that store each record. |
| Lookup concurrency | 10 | fixed | A lookup asks 22 to 39 servers (measured in the simulator with 30 to 300 servers). |
| Servers asked per lookup | 100 | fixed | Bounds a lookup that liars keep feeding new nodes. |
| Relays per `Connect` | 3, one after another | fixed | Lets `Connect` go past a relay that fails or lies, and bounds the requests of one `Connect`. |
| Check pings at once | 10 | fixed | Bounds the pings a node sends to check new servers. |
| Check pings toward one /24 | 4 a second (1 per address, 40 in all) | fixed | Bounds the pings that requests with the server flag make a node send. |
| Bootstrap addresses used | 64 | fixed | Bounds the pings one `Bootstrap` sends. |
| Table maintenance | 5 pings every 40s, to entries silent for 15 minutes | fixed | Bounds maintenance traffic; an idle node gets its NAT samples from these pings (see [protocol.md](protocol.md)). |
| Silence before an entry can be replaced | 15 minutes | fixed | Resists eclipse attacks (see the references in protocol.md): at one minute, a flood of newcomers pings the oldest entry again every minute, and one lost reply gives its place away. |
| Failed requests before an entry is dropped | 4 in a row | fixed | Tolerates loss: kolo-dht sends one datagram per request. |
| Entries per IPv4 /24 | 2 per bucket, 10 in the table | fixed | Eclipse bound (see the eclipse papers in protocol.md). |
| Record lifetime | 20 minutes after its last refresh | fixed | Bounds how long a server keeps a record after its announcer stops refreshing it. |
| Record refresh | every 15s, to every server that stored it | fixed | Keeps the announcer's NAT open toward every storer, since each one can relay: 20 storers every 15s is 1.3 datagrams a second per topic. |
| New lookup of an announced topic | every 5 minutes | fixed | Keeps the record at the servers now closest to the topic, and gives an announcing node about 20 NAT samples every 5 minutes. |
| Round-trip token | secret changes every 40s, so a token lives 40 to 80s; bound to IPv4 address and port | fixed | The longest measured gap between a reply and the request that uses its token is 31s (see [protocol.md](protocol.md)), so 40s covers it with 9s to spare; a refresh uses the token of the previous ANNOUNCE reply 15s later. The port stays in the token, so peers behind one shared IPv4 address cannot use each other's. |
| Relays at once per requester host, per target | 2, 4 | fixed | Bound what one host can make a server do, and the PUNCH requests one announcer gets. |
| Punch attempts at once per destination host | 2 (at the announcer and at the connector) | fixed | Bounds the probes toward one host. |
| Probe interval | 1s with two consistent mappings; 20ms for random-port probes and the birthday keep-alive, which starts 100ms after the sockets open | fixed | Sets the probe windows: 10 probes 1s apart, and 1750 random-port probes 20ms apart (35s). |
| Probes before the peer echoes, answers to probes | 10 with two consistent mappings (1 at the announcer); 1750 to random ports 1000 to 65535 of the verified IP with a random one; 4 answers per punch | fixed | Bounds the probes before an address is proved. The announcer sends one probe per PUNCH before an echo, so a lying server, or a record that names a stranger, makes a node send at most 1 probe at the announcer (`TestPunchVictim`) and 10 per attempt at the connector (`TestSybilRecordsVictim`); a random punch sends at most one window of 35-byte probes to one IP (`TestPunchRandomVictim`), per `RandomPunchCooldown`. A PUNCH needs its storer's MAC (`TestPunchNeedsMAC`), and the connector probes random ports only of an IP that servers in two /16s stored (`TestLyingRelayRandomVictim`), after the peer signed its OK for that IP (`TestReplayedRecordNoProbes`). |
| Birthday punch (one random mapping) | 256 sockets, the node's own included; each new socket's packets at TTL 5 until the peer reaches one of them | fixed | Finds an open mapping with probability about 0.999 (see [protocol.md](protocol.md)). TTL 5 opens our own NAT and dies before the peer's, so a wrong address gets only packets that reach hosts within 4 hops. Measured only in the simulator. |
| Addresses a punch session sends to | 8 | fixed | Bounds the memory of a session. |
| Signature checks per `Lookup` | 160 | fixed | Bounds the CPU of one `Lookup` (20 replies of 16 records would be 320). |
| NAT sample window | 16, one per server /24 | fixed | One sample per server /24, so each lying sample needs its own /24 (see [protocol.md](protocol.md)). |
| Samples needed for a NAT class | 3 | fixed | One lying server cannot set the class: below 3 samples there is no class (see [protocol.md](protocol.md)). |
| NAT sample age | 30 minutes | fixed | kolo-dht samples only the replies to its own requests, and an idle node hears again from each server only every 16 to 17 minutes (measured, see [protocol.md](protocol.md)); at 5 minutes it would be unclassified about two thirds of the time. |
| Change of r (node ID choice) | at most once a minute | fixed | Bounds ID churn when servers share an address. |
| ANNOUNCEs that cost a check (per second: per IPv4 address, per /24, total) | 20, 100, 1000, or the request limit above if lower | fixed | A sender with a valid round-trip token can make a server run a key agreement (a new share) or a signature check (a new or changed record) with random bytes, about 50us each. Past the budget the ANNOUNCE gets no reply and counts as limited; the announcer tries again at its next refresh. A refresh of a stored record (same address, signature and share) costs neither and is not counted. Both checks run without the node lock (`TestAnnounceVerifyBudget`, `TestAnnounceRefreshNotCounted`). |
| Rate limit window | 1s | fixed | Matches the per-second request limits above. |
| Datagram | at most 1200 bytes | fixed | Fits the QUIC initial MTU of 1200 bytes on the socket shared with QUIC. |
| Nodes, records per reply | 20, 16 | fixed | 1200 bytes hold at most 10 records of about 106 bytes, so 16 never binds. |

