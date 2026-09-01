// Package health tracks WAF backend health and manages backoff state.
package health

import (
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// Tracker tracks WAF health: counts failures in a tumbling window,
// trips to unhealthy after threshold, auto-recovers after backoff timeout.
type Tracker struct {
	mu               sync.RWMutex
	isShutdown       atomic.Bool // lockless fast path for IsUnhealthy()
	shutdownUntil    time.Time
	failureCount     int
	lastFailureReset time.Time
	backoffTimeout   time.Duration
	failureWindow    time.Duration
	failureThreshold int
	logger           *slog.Logger
}

// New creates a new Tracker. When failureThreshold < 0,
// the tracker never trips (opt-out). When failureWindow is 0, the counter never resets.
func New(backoffTimeout, failureWindow time.Duration, failureThreshold int, logger *slog.Logger) *Tracker {
	return &Tracker{
		backoffTimeout:   backoffTimeout,
		failureWindow:    failureWindow,
		failureThreshold: failureThreshold,
		logger:           logger,
	}
}

// RecordFailure records a failure and returns true if the tracker just tripped to unhealthy.
// When failureThreshold < 0, always returns false (never trip).
func (ht *Tracker) RecordFailure() bool {
	if ht.failureThreshold < 0 {
		return false
	}

	ht.mu.Lock()
	defer ht.mu.Unlock()

	now := time.Now()

	// Reset failure count if window has elapsed (tumbling window)
	if ht.failureWindow > 0 && now.Sub(ht.lastFailureReset) > ht.failureWindow {
		ht.failureCount = 0
		ht.lastFailureReset = now
	}

	ht.failureCount++

	// Trip if threshold reached
	if ht.failureThreshold >= 0 && ht.failureCount >= ht.failureThreshold {
		ht.isShutdown.Store(true)
		ht.shutdownUntil = now.Add(ht.backoffTimeout)
		ht.logger.Error("marking modsec as unhealthy fail to send HTTP request to modsec", "backoff", ht.backoffTimeout, "failures", ht.failureCount)
		return true
	}
	return false
}

// IsUnhealthy returns true if the WAF is currently in unhealthy (backoff) state.
// Uses a lockless fast-path when not shutdown; auto-recovers when shutdownUntil has passed.
func (ht *Tracker) IsUnhealthy() bool {
	// Fast path: lockless read when not shutdown
	if !ht.isShutdown.Load() {
		return false
	}

	// Check if backoff has expired and recover
	ht.mu.Lock()
	defer ht.mu.Unlock()
	if ht.isShutdown.Load() && time.Now().After(ht.shutdownUntil) {
		ht.isShutdown.Store(false)
		ht.failureCount = 0
		ht.logger.Info("modsec unhealthy backoff expired")
		return false
	}
	return ht.isShutdown.Load()
}
