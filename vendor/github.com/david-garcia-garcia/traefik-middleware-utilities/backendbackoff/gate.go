// Package backendbackoff is a Yaegi-safe in-memory admission gate for an unhealthy backend.
package backendbackoff

import (
	"errors"
	"math/rand"
	"sync"
	"time"
)

var (
	errRatio   = errors.New("backendbackoff: FailureRatio must be in (0, 1)")
	errTrip    = errors.New("backendbackoff: TripFailures must be at least 1")
	errBase    = errors.New("backendbackoff: BaseCooldown must be greater than 0")
	errMax     = errors.New("backendbackoff: MaxCooldown must be at least BaseCooldown")
	errJitter  = errors.New("backendbackoff: Jitter must be in [0, 1)")
	errTTL     = errors.New("backendbackoff: TTL must be at least 1s")
	errClosed  = errors.New("backendbackoff: gate is closed")
	errUnknown = errors.New("backendbackoff: unknown key state")
)

const (
	defaultFailureRatio = 0.30
	defaultTripFailures = 5
	defaultBaseCooldown = time.Second
	defaultMaxCooldown  = 10 * time.Second
	defaultJitter       = 0.10
	defaultTTL          = 60 * time.Second
	maxMemorySources    = 65536
)

// Config is the knobs for a Gate. A fully zero Config applies packaged defaults.
// On a partial Config, a zero Jitter disables jitter (tests freeze cooldowns that way).
type Config struct {
	FailureRatio float64
	TripFailures int
	BaseCooldown time.Duration
	MaxCooldown  time.Duration
	Jitter       float64
	TTL          time.Duration
}

// gateState is CLOSED, OPEN, or HALF-OPEN for one key.
type gateState int

const (
	stateClosed gateState = iota
	stateOpen
	stateHalfOpen
)

// Gate is an in-process per-key backoff gate.
type Gate struct {
	cfg    Config
	budget float64
	now    func() time.Time
	rng    *rand.Rand

	mu     sync.Mutex
	closed bool
	keys   map[string]*memEntry
}

// memEntry is one key's credit, backoff exponent, and idle expire time.
type memEntry struct {
	credit           float64
	n                int
	state            gateState
	openUntil        time.Time
	closedSince      time.Time
	probeUntil       time.Time
	probeOutstanding bool
	expireAt         time.Time
}

// New builds an in-process gate. Zero Config applies defaults.
func New(cfg Config) (*Gate, error) {
	resolved, err := resolveConfig(cfg)
	if err != nil {
		return nil, err
	}
	return &Gate{
		cfg:    resolved,
		budget: float64(resolved.TripFailures),
		now:    time.Now,
		rng:    rand.New(rand.NewSource(time.Now().UnixNano())), //nolint:gosec // G404: cooldown jitter, not a secret
		keys:   map[string]*memEntry{},
	}, nil
}

// resolveConfig fills zero fields then rejects knobs that cannot trip or wait.
func resolveConfig(cfg Config) (Config, error) {
	allZero := cfg == Config{}
	if cfg.FailureRatio == 0 {
		cfg.FailureRatio = defaultFailureRatio
	}
	if cfg.TripFailures == 0 {
		cfg.TripFailures = defaultTripFailures
	}
	if cfg.BaseCooldown == 0 {
		cfg.BaseCooldown = defaultBaseCooldown
	}
	if cfg.MaxCooldown == 0 {
		cfg.MaxCooldown = defaultMaxCooldown
	}
	if cfg.TTL == 0 {
		cfg.TTL = defaultTTL
	}
	if allZero {
		cfg.Jitter = defaultJitter
	}
	if cfg.FailureRatio <= 0 || cfg.FailureRatio >= 1 {
		return Config{}, errRatio
	}
	if cfg.TripFailures < 1 {
		return Config{}, errTrip
	}
	if cfg.BaseCooldown <= 0 {
		return Config{}, errBase
	}
	if cfg.MaxCooldown < cfg.BaseCooldown {
		return Config{}, errMax
	}
	if cfg.Jitter < 0 || cfg.Jitter >= 1 {
		return Config{}, errJitter
	}
	if cfg.TTL < time.Second {
		return Config{}, errTTL
	}
	return cfg, nil
}

// Close drops stored keys. Later Allow and Report return errClosed.
func (g *Gate) Close() {
	g.mu.Lock()
	g.closed = true
	g.keys = nil
	g.mu.Unlock()
}

// SetNowForTest replaces the clock. Production callers must not use this.
func (g *Gate) SetNowForTest(now func() time.Time) {
	if now == nil {
		g.now = time.Now
		return
	}
	g.now = now
}

// successCredit is p/(1-p) added on a successful Report.
func (g *Gate) successCredit() float64 {
	return g.cfg.FailureRatio / (1 - g.cfg.FailureRatio)
}

// cooldownDuration is BaseCooldown * 2^n, jittered, capped at MaxCooldown.
func (g *Gate) cooldownDuration(n int) time.Duration {
	wait := g.cfg.BaseCooldown
	// Double until MaxCooldown rather than 2^n in float.
	for i := 0; i < n; i++ {
		if wait > g.cfg.MaxCooldown/2 {
			wait = g.cfg.MaxCooldown
			break
		}
		wait *= 2
	}
	if wait > g.cfg.MaxCooldown {
		wait = g.cfg.MaxCooldown
	}
	if g.cfg.Jitter <= 0 {
		return wait
	}
	// Spread wait by ±Jitter so replicas that trip together do not probe in lockstep.
	jitterSample := g.rng.Float64()
	jittered := time.Duration(float64(wait) * (1 + g.cfg.Jitter*(2*jitterSample-1)))
	if jittered < 0 {
		jittered = 0
	}
	if jittered > g.cfg.MaxCooldown {
		return g.cfg.MaxCooldown
	}
	return jittered
}
