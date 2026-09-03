package modsecurity

import (
	"io"
	"net/http"
	"runtime"
	"sync"
	"sync/atomic"
)

// pooledBodyGate Put's a pooled inbound buffer only after every registered consumer finishes.
type pooledBodyGate struct {
	release func()
	pending int32
	once    sync.Once
}

// newPooledBodyGate registers how many consumers must finish before release runs.
func newPooledBodyGate(release func(), consumers int32) *pooledBodyGate {
	return &pooledBodyGate{
		release: release,
		pending: consumers,
	}
}

// consumerDone marks one consumer finished; the last one Put's the pooled buffer.
func (g *pooledBodyGate) consumerDone() {
	if atomic.AddInt32(&g.pending, -1) == 0 {
		g.once.Do(g.release)
	}
}

// doneReadCloser is one consumer's view of a shared body slice. Close makes this
// reader unusable; a sibling reader on the same slice is unaffected until it Closes.
type doneReadCloser struct {
	inner  io.ReadCloser
	mu     sync.Mutex
	closed bool
	once   sync.Once
	done   func()
}

// newDoneReadCloser wraps r and calls done once on Close, or from a finalizer if Close
// never runs after this reader is unreachable. Close remains the timely path while
// Transport or next holds the closer.
//
// Finalizer note: production Traefik loads this module as a compiled Go plugin, so
// runtime.SetFinalizer works. Under Yaegi (experimental.localPlugins / --experimental.plugins),
// finalizers registered from interpreted code typically never fire — treat Close on every
// exit path as the only reliable release mechanism; the finalizer is a native safety net only.
// done must be non-nil (callers that need a plain reader should use io.NopCloser).
func newDoneReadCloser(r io.Reader, done func()) *doneReadCloser {
	d := &doneReadCloser{
		inner: io.NopCloser(r),
		done:  done,
	}
	runtime.SetFinalizer(d, (*doneReadCloser).releaseIfAbandoned)
	return d
}

// Read copies from the inner reader until Close; after Close it returns http.ErrBodyReadAfterClose.
func (d *doneReadCloser) Read(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return 0, http.ErrBodyReadAfterClose
	}
	return d.inner.Read(p)
}

// Close marks this reader closed, then signals done outside the mutex so done/Put
// cannot deadlock a concurrent Read on this instance.
func (d *doneReadCloser) Close() error {
	runtime.SetFinalizer(d, nil)
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil
	}
	d.closed = true
	err := d.inner.Close()
	d.mu.Unlock()
	d.once.Do(d.done)
	return err
}

// releaseIfAbandoned treats an unreachable, never-Closed reader as finished for the gate.
// Only the finalizer may call this; the object is unreachable so no concurrent Read exists.
func (d *doneReadCloser) releaseIfAbandoned() {
	d.once.Do(d.done)
}

// closeInboundBodyConsumer closes body when present so a doneReadCloser can release a pooled buffer.
func closeInboundBodyConsumer(body io.ReadCloser) {
	if body != nil {
		_ = body.Close()
	}
}
