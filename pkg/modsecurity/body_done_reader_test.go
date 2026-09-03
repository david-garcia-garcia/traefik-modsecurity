package modsecurity

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
)

// TestPooledBodyGate_LastConsumerReleasesOnce covers gate semantics (Opus L8).
func TestPooledBodyGate_LastConsumerReleasesOnce(t *testing.T) {
	var releases atomic.Int32
	gate := newPooledBodyGate(func() { releases.Add(1) }, 2)

	gate.consumerDone()
	if releases.Load() != 0 {
		t.Fatal("first consumer must not release")
	}
	gate.consumerDone()
	if releases.Load() != 1 {
		t.Fatalf("releases %d, want 1", releases.Load())
	}
	gate.consumerDone() // extra should be a no-op via once
	if releases.Load() != 1 {
		t.Fatalf("extra consumerDone released again: %d", releases.Load())
	}
}

// TestDoneReadCloser_ReadAfterCloseReturnsErrBodyReadAfterClose (Opus L8).
func TestDoneReadCloser_ReadAfterCloseReturnsErrBodyReadAfterClose(t *testing.T) {
	d := newDoneReadCloser(bytes.NewReader([]byte("hello")), func() {})
	if err := d.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	n, err := d.Read(make([]byte, 1))
	if n != 0 || !errors.Is(err, http.ErrBodyReadAfterClose) {
		t.Fatalf("Read after Close: n=%d err=%v, want 0 and ErrBodyReadAfterClose", n, err)
	}
}

// TestDoneReadCloser_CloseIsIdempotent (Opus L8).
func TestDoneReadCloser_CloseIsIdempotent(t *testing.T) {
	var doneCalls atomic.Int32
	d := newDoneReadCloser(bytes.NewReader([]byte("x")), func() { doneCalls.Add(1) })
	if err := d.Close(); err != nil {
		t.Fatalf("Close 1: %v", err)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("Close 2: %v", err)
	}
	if doneCalls.Load() != 1 {
		t.Fatalf("done calls %d, want 1", doneCalls.Load())
	}
}

// TestDoneReadCloser_SiblingUnaffectedBySiblingClose (Opus L8).
func TestDoneReadCloser_SiblingUnaffectedBySiblingClose(t *testing.T) {
	payload := []byte("shared-payload")
	var releases atomic.Int32
	gate := newPooledBodyGate(func() { releases.Add(1) }, 2)
	a := newDoneReadCloser(bytes.NewReader(payload), gate.consumerDone)
	b := newDoneReadCloser(bytes.NewReader(payload), gate.consumerDone)

	_ = a.Close()
	if releases.Load() != 0 {
		t.Fatal("one sibling Close must not release the gate")
	}
	got, err := io.ReadAll(b)
	if err != nil {
		t.Fatalf("sibling ReadAll: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("sibling got %q, want %q", got, payload)
	}
	_ = b.Close()
	if releases.Load() != 1 {
		t.Fatalf("releases %d, want 1 after both Close", releases.Load())
	}
}
