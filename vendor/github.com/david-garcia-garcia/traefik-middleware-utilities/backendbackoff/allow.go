package backendbackoff

import (
	"context"
	"time"
)

// Allow returns whether a backend attempt for key may proceed, plus how long to wait if not.
func (g *Gate) Allow(ctx context.Context, key string) (bool, time.Duration, error) {
	if err := ctx.Err(); err != nil {
		return false, 0, err
	}
	now := g.now()
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return false, 0, errClosed
	}
	entry := g.loadEntry(key, now)
	// Idle longer than ttl is a new key. Refresh so OPEN denies do not drop the map slot.
	entry.expireAt = now.Add(g.cfg.TTL)
	switch entry.state {
	case stateClosed:
		g.resetNIfClosedLongEnough(entry, now)
		return true, 0, nil
	case stateOpen:
		if now.Before(entry.openUntil) {
			return false, entry.openUntil.Sub(now), nil
		}
		entry.state = stateHalfOpen
		entry.probeOutstanding = true
		entry.probeUntil = now.Add(g.cfg.BaseCooldown)
		return true, 0, nil
	case stateHalfOpen:
		if entry.probeOutstanding && now.Before(entry.probeUntil) {
			return false, entry.probeUntil.Sub(now), nil
		}
		entry.probeOutstanding = true
		entry.probeUntil = now.Add(g.cfg.BaseCooldown)
		return true, 0, nil
	default:
		return false, 0, errUnknown
	}
}

// Report records the outcome of a real backend attempt the gate admitted.
func (g *Gate) Report(key string, success bool) error {
	now := g.now()
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return errClosed
	}
	entry := g.keys[key]
	if entry == nil {
		return nil
	}
	// Expire is Allow's job. An admitted attempt that Reports after TTL still lands.
	entry.expireAt = now.Add(g.cfg.TTL)
	switch entry.state {
	case stateOpen:
		return nil
	case stateHalfOpen:
		if !entry.probeOutstanding {
			return nil
		}
		entry.probeOutstanding = false
		if success {
			entry.credit = g.budget
			entry.state = stateClosed
			entry.closedSince = now
			return nil
		}
		entry.n++
		entry.state = stateOpen
		entry.openUntil = now.Add(g.cooldownDuration(entry.n))
		return nil
	case stateClosed:
		if success {
			entry.credit += g.successCredit()
			if entry.credit > g.budget {
				entry.credit = g.budget
			}
			return nil
		}
		g.resetNIfClosedLongEnough(entry, now)
		entry.credit--
		if entry.credit <= 0 {
			entry.state = stateOpen
			entry.openUntil = now.Add(g.cooldownDuration(entry.n))
			entry.closedSince = time.Time{}
		}
		return nil
	default:
		return errUnknown
	}
}

// loadEntry returns the key's slot, dropping it first when idle TTL has elapsed.
func (g *Gate) loadEntry(key string, now time.Time) *memEntry {
	entry := g.keys[key]
	if entry != nil && !now.Before(entry.expireAt) {
		delete(g.keys, key)
		entry = nil
	}
	if entry == nil {
		g.dropExpired(now)
		if len(g.keys) >= maxMemorySources {
			g.dropOne(now)
		}
		entry = &memEntry{
			credit:      g.budget,
			state:       stateClosed,
			closedSince: now,
		}
		g.keys[key] = entry
	}
	return entry
}

// resetNIfClosedLongEnough sets n to 0 after one MaxCooldown of continuous CLOSED.
func (g *Gate) resetNIfClosedLongEnough(entry *memEntry, now time.Time) {
	if entry.closedSince.IsZero() {
		return
	}
	if now.Before(entry.closedSince.Add(g.cfg.MaxCooldown)) {
		return
	}
	entry.n = 0
}

// dropExpired removes keys whose ttl has elapsed.
func (g *Gate) dropExpired(now time.Time) {
	for key, entry := range g.keys {
		if !now.Before(entry.expireAt) {
			delete(g.keys, key)
		}
	}
}

// dropOne removes one map slot when at cap so a new key can be stored.
func (g *Gate) dropOne(now time.Time) {
	g.dropExpired(now)
	if len(g.keys) < maxMemorySources {
		return
	}
	for key := range g.keys {
		delete(g.keys, key)
		return
	}
}
