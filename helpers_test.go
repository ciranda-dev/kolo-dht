package kolodht

import (
	"context"
	"io"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"testing"
	"time"

	koloid "github.com/ciranda-dev/kolo-id"
	kolosecure "github.com/ciranda-dev/kolo-secure"
)

// checkGoroutines fails the test if goroutines started during it outlive its cleanups.
func checkGoroutines(t *testing.T) {
	t.Helper()
	before := goroutines()
	t.Cleanup(func() {
		deadline := time.Now().Add(5 * time.Second)
		for {
			var leaked []string
			for id, stack := range goroutines() {
				if _, ok := before[id]; !ok {
					leaked = append(leaked, stack)
				}
			}
			if len(leaked) == 0 {
				return
			}
			if time.Now().After(deadline) {
				t.Errorf("%d goroutines leaked:\n%s", len(leaked), strings.Join(leaked, "\n\n"))
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
}

func goroutines() map[string]string {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	out := make(map[string]string)
	for _, stack := range strings.Split(string(buf), "\n\n") {
		if id, _, ok := strings.Cut(strings.TrimPrefix(stack, "goroutine "), " "); ok {
			out[id] = stack
		}
	}
	return out
}

func ident(t testing.TB) *koloid.Identity {
	t.Helper()
	id, err := koloid.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func testCtx(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

func fastConfig(server bool) *Config {
	return &Config{
		Server:         server,
		RequestTimeout: 300 * time.Millisecond,
		PunchTimeout:   3 * time.Second,
		Secure:         &kolosecure.Config{HandshakeTimeout: 2 * time.Second},
	}
}

// loopNode starts a node on loopback with the public API.
func loopNode(t *testing.T, cfg *Config) *Node {
	t.Helper()
	n, err := New(context.Background(), "127.0.0.1:0", ident(t), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Close() })
	return n
}

func addrOf(n *Node) netip.AddrPort {
	ap := n.Addr().(*net.UDPAddr).AddrPort()
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

func topicOf(s string) (t Topic) {
	copy(t[:], s)
	return t
}

// echo checks a stream round trip from a to b over connections that are already authenticated.
func echo(t *testing.T, ctx context.Context, a, b *kolosecure.Conn) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		s, err := b.AcceptStream(ctx)
		if err != nil {
			done <- err
			return
		}
		_, err = io.Copy(s, s)
		s.Close()
		done <- err
	}()
	s, err := a.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write([]byte("hello kolo")); err != nil {
		t.Fatal(err)
	}
	s.Close()
	got, err := io.ReadAll(s)
	if err != nil || string(got) != "hello kolo" {
		t.Fatalf("echo: %q %v", got, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
