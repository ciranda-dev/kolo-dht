package kolodht

import (
	"bytes"
	"net/netip"
	"testing"
	"time"
)

func TestAnnounceLookupConnect(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t, 20*time.Second)
	s := loopNode(t, fastConfig(true))
	a := loopNode(t, fastConfig(false))
	b := loopNode(t, fastConfig(false))
	for _, n := range []*Node{a, b} {
		if err := n.Bootstrap(ctx, []netip.AddrPort{addrOf(s)}); err != nil {
			t.Fatal(err)
		}
	}
	topic := topicOf("loopback")
	if err := b.Announce(ctx, topic); err != nil {
		t.Fatal(err)
	}
	recs, err := a.Lookup(ctx, topic)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || !bytes.Equal(recs[0].PublicKey, b.id.PublicKey()) || recs[0].Addr != addrOf(b) || recs[0].Topic != topic {
		t.Fatalf("Lookup = %+v", recs)
	}
	if own, err := b.Lookup(ctx, topic); err != nil || len(own) != 0 {
		t.Fatalf("announcer sees %d records of its own topic, %v", len(own), err)
	}
	ca, err := a.Connect(ctx, recs[0])
	if err != nil {
		t.Fatal(err)
	}
	defer ca.Close()
	if !bytes.Equal(ca.RemotePublicKey(), b.id.PublicKey()) {
		t.Fatal("Connect reached another key")
	}
	cb, err := b.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer cb.Close()
	if !bytes.Equal(cb.RemotePublicKey(), a.id.PublicKey()) {
		t.Fatal("Accept returned another key")
	}
	echo(t, ctx, ca, cb)
	// The connection uses the node's own socket, the one the DHT announced.
	if got := ca.LocalAddr().String(); got != a.Addr().String() {
		t.Fatalf("connection from %s, node socket %s", got, a.Addr())
	}

	b.Unannounce(topic)
	if err := b.Announce(ctx, topic); err != nil {
		t.Fatalf("Announce after Unannounce: %v", err)
	}
}
