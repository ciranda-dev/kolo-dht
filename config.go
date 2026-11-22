package kolodht

import (
	"fmt"
	"time"

	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

// Config sets the limits of a Node. A zero field takes its default; out of range is ErrInvalidConfig.
type Config struct {
	// Secure is passed to kolo-secure, and Secure.Transport to kolotransport.Listen. A zero Transport.KeepAlivePeriod
	// becomes 5s, so NAT filters stay open for punched connections, unless Transport.IdleTimeout is 5s or less.
	Secure *kolosecure.Config
	// Server answers DHT queries, stores records and relays connect requests; only servers enter routing tables.
	Server bool
	// MaxRecords caps the records a server stores, all topics. Default 65536, from 16 to 1,000,000.
	// A full store takes about MaxRecords x 710 bytes of heap, 44 MiB at the default.
	MaxRecords int
	// MaxRecordsPerTopic caps the records of one topic. Default 512, from 1 to 65536. One IPv4 /24 may hold a sixteenth
	// of them (at least 1), so filling a topic takes 16 networks.
	MaxRecordsPerTopic int
	// MaxRecordsPerIP caps the records from one announcing IPv4 address, all topics. Default 256, from 1 to 65536.
	MaxRecordsPerIP int
	// MaxAnnouncements caps the topics this node announces at once. Zero means no cap; negative is ErrInvalidConfig.
	MaxAnnouncements int
	// MaxInflight caps the requests waiting for a reply. Default 160, from 8 to 4096.
	MaxInflight int
	// MaxRelays caps the connect requests a server relays at once. Default 64, from 1 to 4096.
	MaxRelays int
	// MaxPunches caps the punch requests this node answers at once, and the live connections punches made on birthday
	// sockets of their own (4 per /24); a new one past that is refused. Default 16, from 1 to 256.
	MaxPunches int
	// MaxRequestsPerIP caps the requests per second from one IPv4 address. Default 50, from 1 to 10,000.
	MaxRequestsPerIP int
	// MaxRequestsPerPrefix caps the requests per second from one IPv4 /24. Default 200, from MaxRequestsPerIP to 100,000.
	MaxRequestsPerPrefix int
	// MaxRequests caps the requests per second from everyone. Default 10,000, from MaxRequestsPerPrefix to 1,000,000.
	MaxRequests int
	// RequestTimeout bounds the wait for one reply. Default 1s, from 100ms to 10s.
	RequestTimeout time.Duration
	// PunchTimeout bounds one connect attempt through one relay, a 35s random punch included. Default 45s, from 1s to 2m.
	PunchTimeout time.Duration
	// MaxRandomPunches caps the punches with a random mapping on one side that this node runs at once.
	// Default 1, from 1 to 16.
	MaxRandomPunches int
	// MaxRandomPunchesPerTarget caps the random punches toward one peer IPv4 address. Default 1, from 1 to MaxRandomPunches.
	MaxRandomPunchesPerTarget int
	// MaxRandomPunchesPerRequester caps the random punches answered for one requester IPv4 address. Default 1, from 1 to
	// MaxRandomPunches.
	MaxRandomPunchesPerRequester int
	// RandomPunchInterval is the least time from the end of one random punch to the next. Default 20s, from 1s to 10m.
	RandomPunchInterval time.Duration
	// MaxPunchSockets caps the sockets running punches hold besides the node's own; a birthday punch needs 255. Default
	// 256, or half the soft RLIMIT_NOFILE if less, from 1 to 16384.
	MaxPunchSockets int
	// RandomPunchCooldown is the least time from the end of a burst to the next toward its IP (and /24 at the announcer)
	// or by its storer, doubled per burst toward the IP that connected nothing, up to 16x. Default 1m, from 1s to 1h.
	RandomPunchCooldown time.Duration
	// MaxRandomPunchesPerMinute caps those bursts started in any minute. Default 4, from 1 to 64.
	MaxRandomPunchesPerMinute int
	// Trace, if set, gets every punch probe and step, from the punch goroutines and never with a lock held. It must
	// return fast; a slow one slows the probes. A panic in it drops that event and is not passed on. Default nil.
	Trace func(TraceEvent)
}

type limit[T int | time.Duration] struct {
	name          string
	def, min, max T
}

func (l limit[T]) apply(v *T) error {
	switch {
	case *v == 0:
		*v = l.def
	case *v < l.min || *v > l.max:
		return fmt.Errorf("%w: %s must be between %v and %v", ErrInvalidConfig, l.name, l.min, l.max)
	}
	return nil
}

// DefaultRandomPunchInterval is the default Config.RandomPunchInterval.
const DefaultRandomPunchInterval = 20 * time.Second

const (
	keepAlive      = 5 * time.Second
	defaultIdle    = 30 * time.Second
	defaultPending = 64
)

func (c *Config) withDefaults() (Config, error) {
	var out Config
	if c != nil {
		out = *c
	}
	ints := []struct {
		l limit[int]
		v *int
	}{
		{limit[int]{"MaxRecords", 65536, 16, 1_000_000}, &out.MaxRecords},
		{limit[int]{"MaxRecordsPerTopic", 512, 1, 65536}, &out.MaxRecordsPerTopic},
		{limit[int]{"MaxRecordsPerIP", 256, 1, 65536}, &out.MaxRecordsPerIP},
		{limit[int]{"MaxInflight", 160, 8, 4096}, &out.MaxInflight},
		{limit[int]{"MaxRelays", 64, 1, 4096}, &out.MaxRelays},
		{limit[int]{"MaxPunches", 16, 1, 256}, &out.MaxPunches},
		{limit[int]{"MaxRequestsPerIP", 50, 1, 10_000}, &out.MaxRequestsPerIP},
		{limit[int]{"MaxRandomPunches", 1, 1, 16}, &out.MaxRandomPunches},
		{limit[int]{"MaxPunchSockets", socketDefault(softNoFile()), 1, 16384}, &out.MaxPunchSockets},
		{limit[int]{"MaxRandomPunchesPerMinute", 4, 1, 64}, &out.MaxRandomPunchesPerMinute},
	}
	if out.MaxAnnouncements < 0 {
		return Config{}, fmt.Errorf("%w: MaxAnnouncements must not be negative", ErrInvalidConfig)
	}
	for _, f := range ints {
		if err := f.l.apply(f.v); err != nil {
			return Config{}, err
		}
	}
	if err := (limit[int]{"MaxRandomPunchesPerTarget", 1, 1, out.MaxRandomPunches}).apply(&out.MaxRandomPunchesPerTarget); err != nil {
		return Config{}, err
	}
	if err := (limit[int]{"MaxRandomPunchesPerRequester", 1, 1, out.MaxRandomPunches}).apply(&out.MaxRandomPunchesPerRequester); err != nil {
		return Config{}, err
	}
	prefix := limit[int]{"MaxRequestsPerPrefix", max(200, out.MaxRequestsPerIP), out.MaxRequestsPerIP, 100_000}
	if err := prefix.apply(&out.MaxRequestsPerPrefix); err != nil {
		return Config{}, err
	}
	total := limit[int]{"MaxRequests", max(10_000, out.MaxRequestsPerPrefix), out.MaxRequestsPerPrefix, 1_000_000}
	if err := total.apply(&out.MaxRequests); err != nil {
		return Config{}, err
	}
	if err := (limit[time.Duration]{"RequestTimeout", time.Second, 100 * time.Millisecond, 10 * time.Second}).apply(&out.RequestTimeout); err != nil {
		return Config{}, err
	}
	if err := (limit[time.Duration]{"PunchTimeout", 45 * time.Second, time.Second, 2 * time.Minute}).apply(&out.PunchTimeout); err != nil {
		return Config{}, err
	}
	if err := (limit[time.Duration]{"RandomPunchInterval", DefaultRandomPunchInterval, time.Second, 10 * time.Minute}).apply(&out.RandomPunchInterval); err != nil {
		return Config{}, err
	}
	if err := (limit[time.Duration]{"RandomPunchCooldown", time.Minute, time.Second, time.Hour}).apply(&out.RandomPunchCooldown); err != nil {
		return Config{}, err
	}
	return out, nil
}

// perGroup is the share of a topic one IPv4 /24 may hold.
func perGroup(perTopic int) int { return max(1, perTopic/16) }

// socketDefault leaves half of the soft fd limit to kolo-transport and the application; soft < 0 means unknown.
func socketDefault(soft int) int {
	if soft < 0 {
		return 256
	}
	return max(1, min(256, soft/2))
}

// transport returns the kolo-transport config to listen with and the kolo-secure config for NewListener.
func (c Config) transport() (*kolotransport.Config, *kolosecure.Config) {
	var sc kolosecure.Config
	if c.Secure != nil {
		sc = *c.Secure
	}
	var tc kolotransport.Config
	if sc.Transport != nil {
		tc = *sc.Transport
	}
	sc.Transport = nil
	idle := tc.IdleTimeout
	if idle == 0 {
		idle = defaultIdle
	}
	if tc.KeepAlivePeriod == 0 && idle > keepAlive {
		tc.KeepAlivePeriod = keepAlive
	}
	return &tc, &sc
}

func (c Config) acceptQueue() int {
	if c.Secure != nil && c.Secure.MaxPending > 0 {
		return c.Secure.MaxPending
	}
	return defaultPending
}
