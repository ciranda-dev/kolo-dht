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
