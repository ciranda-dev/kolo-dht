package kolodht

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/ciranda-dev/kolo-dht/internal/punch"
	"github.com/ciranda-dev/kolo-dht/internal/ratelimit"
	"github.com/ciranda-dev/kolo-dht/internal/table"
	"github.com/ciranda-dev/kolo-dht/internal/token"
	"github.com/ciranda-dev/kolo-dht/internal/wire"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

func TestConfigDefaults(t *testing.T) {
	c, err := (*Config)(nil).withDefaults()
	if err != nil {
		t.Fatal(err)
	}
	want := Config{
		MaxRecords: 65536, MaxRecordsPerTopic: 512, MaxRecordsPerIP: 256,
		MaxInflight: 160, MaxRelays: 64, MaxPunches: 16,
		MaxRequestsPerIP: 50, MaxRequestsPerPrefix: 200, MaxRequests: 10_000,
		RequestTimeout: time.Second, PunchTimeout: 45 * time.Second,
		MaxRandomPunches: 1, MaxRandomPunchesPerTarget: 1, MaxRandomPunchesPerRequester: 1,
		RandomPunchInterval: 20 * time.Second, MaxPunchSockets: socketDefault(softNoFile()),
		RandomPunchCooldown: time.Minute, MaxRandomPunchesPerMinute: 4,
	}
	c.Secure = nil
	if !reflect.DeepEqual(c, want) {
		t.Fatalf("defaults %+v\nwant     %+v", c, want)
	}
}

func TestConfigRanges(t *testing.T) {
	bad := map[string]Config{
		"MaxRecords low":           {MaxRecords: 15},
		"MaxRecords high":          {MaxRecords: 1_000_001},
		"MaxRecordsPerTopic low":   {MaxRecordsPerTopic: -1},
		"MaxRecordsPerIP low":      {MaxRecordsPerIP: -1},
		"MaxAnnouncements":         {MaxAnnouncements: -1},
		"MaxInflight low":          {MaxInflight: 7},
		"MaxInflight high":         {MaxInflight: 4097},
		"MaxRelays":                {MaxRelays: 4097},
		"MaxPunches":               {MaxPunches: 257},
		"MaxRequestsPerIP":         {MaxRequestsPerIP: 10_001},
		"MaxRequestsPerPrefix low": {MaxRequestsPerIP: 100, MaxRequestsPerPrefix: 99},
		"MaxRequests below prefix": {MaxRequests: 199},
		"MaxRequests high":         {MaxRequests: 1_000_001},
		"RequestTimeout low":       {RequestTimeout: 99 * time.Millisecond},
		"RequestTimeout high":      {RequestTimeout: 11 * time.Second},
		"PunchTimeout low":         {PunchTimeout: 999 * time.Millisecond},
		"PunchTimeout high":        {PunchTimeout: 2*time.Minute + 1},
		"MaxRandomPunches low":     {MaxRandomPunches: -1},
		"MaxRandomPunches high":    {MaxRandomPunches: 17},
		"PerTarget above total":    {MaxRandomPunches: 2, MaxRandomPunchesPerTarget: 3},
		"PerRequester above total": {MaxRandomPunches: 2, MaxRandomPunchesPerRequester: 3},
		"PerTarget default total":  {MaxRandomPunchesPerTarget: 2},
		"RandomPunchInterval low":  {RandomPunchInterval: 999 * time.Millisecond},
		"RandomPunchInterval high": {RandomPunchInterval: 10*time.Minute + 1},
		"MaxPunchSockets low":      {MaxPunchSockets: -1},
		"MaxPunchSockets high":     {MaxPunchSockets: 16385},
		"RandomPunchCooldown low":  {RandomPunchCooldown: 999 * time.Millisecond},
		"RandomPunchCooldown high": {RandomPunchCooldown: time.Hour + 1},
		"PerMinute low":            {MaxRandomPunchesPerMinute: -1},
		"PerMinute high":           {MaxRandomPunchesPerMinute: 65},
	}
	for name, c := range bad {
		if _, err := c.withDefaults(); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s: %v, want ErrInvalidConfig", name, err)
		}
	}
	good := []Config{
		{MaxRecords: 16, MaxRecordsPerTopic: 1, MaxRecordsPerIP: 65536, MaxAnnouncements: 1, MaxInflight: 8, MaxRelays: 1, MaxPunches: 1},
		{MaxRecords: 1_000_000, MaxRecordsPerTopic: 65536, MaxRecordsPerIP: 1, MaxAnnouncements: 1 << 30, MaxInflight: 4096, MaxRelays: 4096, MaxPunches: 256},
		{MaxAnnouncements: 257},
		{MaxRequestsPerIP: 10_000, MaxRequestsPerPrefix: 100_000, MaxRequests: 1_000_000},
		{MaxRequestsPerIP: 1, MaxRequestsPerPrefix: 1, MaxRequests: 1},
		{RequestTimeout: 100 * time.Millisecond, PunchTimeout: 2 * time.Minute},
		{MaxRandomPunches: 16, MaxRandomPunchesPerTarget: 16, MaxRandomPunchesPerRequester: 16},
		{MaxRandomPunchesPerTarget: 1, MaxRandomPunchesPerRequester: 1},
		{RandomPunchInterval: time.Second, MaxPunchSockets: 1},
		{RandomPunchInterval: 10 * time.Minute, MaxPunchSockets: 16384},
		{RandomPunchCooldown: time.Second, MaxRandomPunchesPerMinute: 1},
		{RandomPunchCooldown: time.Hour, MaxRandomPunchesPerMinute: 64},
	}
	for _, c := range good {
		if _, err := c.withDefaults(); err != nil {
			t.Errorf("%+v: %v", c, err)
		}
	}
}

// TestSocketDefault keeps half of the soft RLIMIT_NOFILE for kolo-transport and the application.
func TestSocketDefault(t *testing.T) {
	for soft, want := range map[int]int{0: 1, 1: 1, 256: 128, 511: 255, 512: 256, 92160: 256, -1: 256} {
		if got := socketDefault(soft); got != want {
			t.Errorf("socketDefault(%d) = %d, want %d", soft, got, want)
		}
	}
}

func TestTransportConfig(t *testing.T) {
	c, err := (&Config{}).withDefaults()
	if err != nil {
		t.Fatal(err)
	}
	tc, sc := c.transport()
	if tc.KeepAlivePeriod != 5*time.Second || sc.Transport != nil {
		t.Fatalf("transport %+v, secure transport %v", tc, sc.Transport)
	}
	user := &kolotransport.Config{KeepAlivePeriod: 7 * time.Second}
	c, _ = (&Config{Secure: &kolosecure.Config{Transport: user}}).withDefaults()
	if tc, _ := c.transport(); tc.KeepAlivePeriod != 7*time.Second {
		t.Fatalf("caller's KeepAlivePeriod replaced: %v", tc.KeepAlivePeriod)
	}
	c, _ = (&Config{Secure: &kolosecure.Config{Transport: &kolotransport.Config{IdleTimeout: 5 * time.Second}}}).withDefaults()
	if tc, _ := c.transport(); tc.KeepAlivePeriod != 0 {
		t.Fatalf("KeepAlivePeriod %v with a 5s IdleTimeout", tc.KeepAlivePeriod)
	}
	c, _ = (&Config{Secure: &kolosecure.Config{Transport: &kolotransport.Config{IdleTimeout: 10 * time.Second}}}).withDefaults()
	if tc, _ := c.transport(); tc.KeepAlivePeriod != 5*time.Second {
		t.Fatalf("KeepAlivePeriod %v with a 10s IdleTimeout", tc.KeepAlivePeriod)
	}
	if user.KeepAlivePeriod != 7*time.Second {
		t.Fatal("caller's Config modified")
	}
}

// TestFixedLimits checks the fixed limits and protocol intervals against the table in the README.
func TestFixedLimits(t *testing.T) {
	for _, l := range []struct {
		name      string
		got, want any
	}{
		{"K", table.K, 20},
		{"alpha", alpha, 10},
		{"maxQueries", maxQueries, 100},
		{"maxRelays", maxRelays, 3},
		{"maxChecks", maxChecks, 10},
		{"maxBoot", maxBoot, 64},
		{"staleChecks", staleChecks, 5},
		{"Questionable", table.Questionable, 15 * time.Minute},
		{"MaxFails", table.MaxFails, 4},
		{"MaxGroupBucket", table.MaxGroupBucket, 2},
		{"MaxGroupTable", table.MaxGroupTable, 10},
		{"maxRelaysPerHost", maxRelaysPerHost, 2},
		{"maxRelaysPerTarget", maxRelaysPerTarget, 4},
		{"maxDestAttempts", maxDestAttempts, 2},
		{"perGroup", perGroup(512), 32},
		{"punch.ConsistentTries", punch.ConsistentTries, 10},
		{"punch.RandomTries", punch.RandomTries, 1750},
		{"punch.MinRandomPort", punch.MinRandomPort, 1000},
		{"punch.Sockets", punch.Sockets, 256},
		{"punch.LowTTL", punch.LowTTL, 5},
		{"maxProbeReplies", maxProbeReplies, 4},
		{"maxSentTo", maxSentTo, 8},
		{"maxVerify", maxVerify, 160},
		{"maxSamples", maxSamples, 16},
		{"minSamples", minSamples, 3},
		{"refresh", defaultTiming.refresh, 15 * time.Second},
		{"ttl", defaultTiming.ttl, 20 * time.Minute},
		{"relookup", defaultTiming.relookup, 5 * time.Minute},
		{"maintain", defaultTiming.maintain, 40 * time.Second},
		{"consistentEvery", defaultTiming.consistentEvery, time.Second},
		{"randomEvery", defaultTiming.randomEvery, 20 * time.Millisecond},
		{"keepAliveDelay", defaultTiming.keepAliveDelay, 100 * time.Millisecond},
		{"rChange", defaultTiming.rChange, time.Minute},
		{"sampleAge", defaultTiming.sampleAge, 30 * time.Minute},
		{"token.Rotation", token.Rotation, 40 * time.Second},
		{"ratelimit.Window", ratelimit.Window, time.Second},
		{"wire.MaxSize", wire.MaxSize, 1200},
		{"wire.MaxNodes", wire.MaxNodes, 20},
		{"wire.MaxRecords", wire.MaxRecords, 16},
	} {
		if l.got != l.want {
			t.Errorf("%s = %v, want %v", l.name, l.got, l.want)
		}
	}
}
