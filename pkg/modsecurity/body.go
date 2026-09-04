package modsecurity

import (
	"bytes"
	"io"
	"net/http"
	"sync"
)

// bufferPool is Get and Put for inbound body buffers. *sync.Pool implements it so tests can count Put.
type bufferPool interface {
	Get() any
	Put(any)
}

// newBodyBufferPool returns a pool of bytes.Buffer for inbound body reads.
func newBodyBufferPool() bufferPool {
	return &sync.Pool{
		New: func() interface{} {
			return new(bytes.Buffer)
		},
	}
}

// readInboundBody copies req.Body for the sidecar and next.
// Known length uses this Plugin core's pool only under the pool cap; -1 (unknown) still pools the read
// until the body would exceed the pool cap — then the pool buffer is Put and the full body is owned.
// On a successful pooled read the returned slice is a copy; Put runs before return so a sidecar
// RoundTripper that still Reads Request.Body cannot see a later Get/Reset.
// Put is always handled inside this function (success and error). rw is required for MaxBytesReader;
// the caller writes 413 or 502 when err is non-nil.
//
// Pool+copy-out vs plain io.ReadAll (go test -bench=BenchmarkReadInboundBody -benchmem, win/amd64):
//
//	4KB  ~2.2µs  9.6KB/op  16 allocs  vs  ~4.5µs  22.9KB/op  22 allocs
//	64KB ~13µs   74KB/op   16 allocs  vs  ~45µs   291KB/op   31 allocs
//	1MB  ~123µs  1.26MB/op 17 allocs  vs  ~570µs  5.2MB/op   43 allocs
//
// The pool reuses scratch Cap while reading; the final owned []byte is still allocated either way.
func (p *Plugin) readInboundBody(rw http.ResponseWriter, req *http.Request) (body []byte, err error) {
	if p.maxBodySizeBytes > 0 {
		req.Body = http.MaxBytesReader(rw, req.Body, p.maxBodySizeBytes)
	}

	usePool := true
	if req.ContentLength >= 0 {
		usePool = req.ContentLength <= p.maxBodySizeBytesForPool
	}

	if !usePool {
		return io.ReadAll(req.Body)
	}

	buf := p.bodyBufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	// LimitReader keeps Len <= poolCap; Cap may be ~2x from bytes.Buffer growth — still Put.
	defer p.bodyBufferPool.Put(buf)

	// Bound the pooled read so Cap never grows past the pool threshold on chunked (-1) bodies.
	limited := io.LimitReader(req.Body, p.maxBodySizeBytesForPool)
	n, readErr := io.Copy(buf, limited)
	if readErr != nil {
		return nil, readErr
	}

	if n == p.maxBodySizeBytesForPool {
		// Peek one more byte: if present, body exceeds the pool cap — Put (via defer) and own the rest.
		var peek [1]byte
		extra, peekErr := req.Body.Read(peek[:])
		if peekErr != nil && peekErr != io.EOF {
			return nil, peekErr
		}
		if extra > 0 {
			prefix := append([]byte(nil), buf.Bytes()...)
			rest, restErr := io.ReadAll(req.Body)
			if restErr != nil {
				return nil, restErr
			}
			owned := make([]byte, 0, len(prefix)+extra+len(rest))
			owned = append(owned, prefix...)
			owned = append(owned, peek[0])
			owned = append(owned, rest...)
			return owned, nil
		}
	}

	// Copy out before Put (defer) so sidecar/next never alias a pooled buffer (Yaegi-safe).
	return append([]byte(nil), buf.Bytes()...), nil
}
