package netsim

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
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

func ip(s string) netip.Addr { return netip.MustParseAddr(s) }

// clock is a settable time source for NAT timers.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
}

func listen(t *testing.T, h *Host, port uint16) *Conn {
	t.Helper()
	c, err := h.ListenUDP(port)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func publicHost(t *testing.T, n *Network, addr string) *Host {
	t.Helper()
	h, err := n.AddHost(ip(addr))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func natHost(t *testing.T, n *Network, public, private string, cfg NATConfig) (*NAT, *Host) {
	t.Helper()
	nat, err := n.AddNAT(ip(public), cfg)
	if err != nil {
		t.Fatal(err)
	}
	h, err := nat.AddHost(ip(private))
	if err != nil {
		t.Fatal(err)
	}
	return nat, h
}

func send(t *testing.T, c *Conn, to netip.AddrPort, msg string) {
	t.Helper()
	if _, err := c.WriteTo([]byte(msg), net.UDPAddrFromAddrPort(to)); err != nil {
		t.Fatal(err)
	}
}

// recv reads one packet, or returns ok false if none arrives within wait.
func recv(t *testing.T, c *Conn, wait time.Duration) (msg string, from netip.AddrPort, ok bool) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(wait))
	buf := make([]byte, 2048)
	n, addr, err := c.ReadFrom(buf)
	c.SetReadDeadline(time.Time{})
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return "", netip.AddrPort{}, false
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(buf[:n]), addr.(*net.UDPAddr).AddrPort(), true
}

// observed sends from c to s and returns the source address s sees.
func observed(t *testing.T, c, s *Conn) netip.AddrPort {
	t.Helper()
	send(t, c, s.Addr(), "hello")
	msg, from, ok := recv(t, s, time.Second)
	if !ok || !bytes.Equal([]byte(msg), []byte("hello")) {
		t.Fatalf("server did not receive from %s", c.Addr())
	}
	return from
}

const short = 20 * time.Millisecond
