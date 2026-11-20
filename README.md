# kolo-dht

Find Kolo peers by topic without a central server, and connect to them through NATs.

[![status: experimental](https://img.shields.io/badge/status-experimental-orange)](#status)
[![license: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)
[![go: 1.26+](https://img.shields.io/badge/go-1.26%2B-00ADD8)](go.mod)

## What it is

kolo-dht finds peers with the [Kademlia](https://doi.org/10.1007/3-540-45748-8_5) lookup, hardened after [S/Kademlia](https://doi.org/10.1109/ICPADS.2007.4447808), and connects them through NATs by UDP hole punching as described in [RFC 5128](https://www.rfc-editor.org/info/rfc5128), tested against the NAT behaviors of [RFC 4787](https://www.rfc-editor.org/info/rfc4787). It is a DHT whose requests are single UDP datagrams on the same socket as the node's [kolo-transport](https://github.com/ciranda-dev/kolo-transport) QUIC listener. Peers announce a 32-byte topic with a record signed by their [kolo-id](https://github.com/ciranda-dev/kolo-id) key. The server storing the record relays a connect request, the two peers punch through their NATs, and the caller gets a [kolo-secure](https://github.com/ciranda-dev/kolo-secure) connection pinned to the announced key. When one side's NAT mapping is random, the two punch with the birthday technique.

Nothing relays application data. A pair of NATs that cannot be punched gives `ErrUnreachable`, and an application can opt in to relays, such as kolo-swarm's `Config.Relays`, which dials through kolo-relay.

It is Go only and builds without cgo. It is IPv4 only: IPv6 input is refused with `ErrInvalidArgument`, and a datagram from an IPv6 source is dropped.

## Install

```sh
go get github.com/ciranda-dev/kolo-dht
```

## Quick start

A server and two peers on loopback: one peer announces a topic, the other finds it and connects.

```go
// Command basic runs a server and two peers on loopback: one peer announces a topic, the other finds it and connects.
package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"time"

	kolodht "github.com/ciranda-dev/kolo-dht"
	koloid "github.com/ciranda-dev/kolo-id"
)

func node(ctx context.Context, server bool) *kolodht.Node {
	id, err := koloid.Generate()
	if err != nil {
		log.Fatal(err)
	}
	n, err := kolodht.New(ctx, "127.0.0.1:0", id, &kolodht.Config{Server: server})
	if err != nil {
		log.Fatal(err)
	}
	return n
}

func addr(n *kolodht.Node) netip.AddrPort { return n.Addr().(*net.UDPAddr).AddrPort() }

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	server := node(ctx, true)
	defer server.Close()
	alice, bob := node(ctx, false), node(ctx, false)
	defer alice.Close()
	defer bob.Close()
	for _, n := range []*kolodht.Node{alice, bob} {
		if err := n.Bootstrap(ctx, []netip.AddrPort{addr(server)}); err != nil {
			log.Fatal(err)
		}
	}

	topic := kolodht.Topic(sha256.Sum256([]byte("kolo example topic")))
	if err := bob.Announce(ctx, topic); err != nil {
		log.Fatal(err)
	}
	go func() {
		c, err := bob.Accept(ctx)
		if err != nil {
			return
		}
		s, err := c.AcceptStream(ctx)
		if err != nil {
			return
		}
		io.Copy(s, s)
		s.Close()
	}()

	peers, err := alice.Lookup(ctx, topic)
	if err != nil || len(peers) == 0 {
		log.Fatalf("lookup: %d peers, %v", len(peers), err)
	}
	c, err := alice.Connect(ctx, peers[0])
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()
	s, err := c.OpenStream(ctx)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := s.Write([]byte("hello kolo")); err != nil {
		log.Fatal(err)
	}
	s.Close()
	reply, err := io.ReadAll(s)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s from %x\n", reply, c.RemotePublicKey())
}
```

```text
$ go run .
hello kolo from <64 hex characters>
```

A real deployment runs a few servers (`Config.Server`) on public addresses, such as kolo-node, and peers bootstrap from them.

### Public servers and private networks

`Node.Bootstrap(ctx, nil)` joins the public network, by design, so an application works with no setup: with a nil list it uses the entry nodes built into the library, which Ciranda runs for everyone and which `PublicServers` returns. To add or remove one, edit the list in `public.go`; it holds public IPv4 `host:port` data and nothing else.

Who sees what when the list is nil:

- The two entry nodes see your IP address and port as soon as you bootstrap.
- After `Announce`, the topic and your address are stored on the public network's servers, readable by anyone who looks the topic up. The topic is not a secret: whoever knows its 32 bytes can find the record.
- The entry nodes have no key, so a client cannot check who answers at an address, and the addresses are compiled into each release: a client of an old release keeps asking those addresses. Records are still verified and every connection is pinned to the announced key, so an entry node cannot impersonate a peer, but it can hand a client a bad server list or not answer.

A nil slice counts as nil: a `[]netip.AddrPort` variable that you never appended to also joins the public network. To stay private, pass your own servers. An empty list that is not nil is refused with `ErrInvalidArgument` and sends no packet, so an application that reads its servers from a setting should send the empty case to its own error. Start your first node, run kolo-node on it with `-first`, then give its address to every other node. Keep at least one such node running: a network with no server that stays up has nobody to join.

## API

| Symbol | What it does |
|---|---|
| `New` | Open one UDP socket for the DHT and for kolo-secure connections as an identity |
| `Node.Bootstrap` | Ping servers and fill the routing table; nil servers joins the public network (`PublicServers`) |
| `PublicServers` | A copy of the built-in public entry nodes |
| `Node.Announce`, `Node.Unannounce` | Store a signed record at the servers closest to a topic, and keep it fresh |
| `Node.Lookup` | Return the verified records of a topic |
| `Node.Connect` | Relay a connect request, punch, and return a kolo-secure connection to the record's key |
| `Node.Accept` | Return the next inbound connection, punched or direct |
| `Node.Stats` | Routing table size, records stored and request counters |
| `Topic`, `Record` | A 32-byte topic, and a signed announcement with the addresses to try |
| `Config` | Server mode, store and rate limits, punch limits, timeouts and a `Trace` hook |

Errors are sentinels for `errors.Is`: `ErrInvalidConfig`, `ErrInvalidArgument`, `ErrClosed`, `ErrNoNodes`, `ErrNotStored`, `ErrUnreachable` and `ErrTryLater`.

## Documentation

- [Guide](docs/guide.md): every call, tracing a punch and errors.
- [Limits](docs/limits.md): every option with its default, range and reason.
- [Protocol and design](docs/protocol.md): how lookup, announce, NAT classification and punching work, the wire format, what is and is not guaranteed, and references.

## Status

Experimental. The API may change before v1.0.0.

## License

Licensed under either of the [Apache License, Version 2.0](LICENSE) or the [MIT license](LICENSE-MIT), at your option.
