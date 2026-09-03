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
// On a pooled read error, the caller must defer release when it is non-nil.
// rw is required for MaxBytesReader; the caller writes 413 or 502 when err is non-nil.
func (p *Plugin) readInboundBody(rw http.ResponseWriter, req *http.Request) (body []byte, release func(), err error) {
	if p.maxBodySizeBytes > 0 {
		req.Body = http.MaxBytesReader(rw, req.Body, p.maxBodySizeBytes)
	}

	usePool := true
	if req.ContentLength >= 0 {
		usePool = req.ContentLength <= p.maxBodySizeBytesForPool
	}

	if !usePool {
		largeBody, readErr := io.ReadAll(req.Body)
		if readErr != nil {
			return nil, nil, readErr
		}
		return largeBody, nil, nil
	}

	buf := p.bodyBufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	// LimitReader keeps Len <= poolCap; Cap may be ~2x from bytes.Buffer growth — still Put.
	release = func() {
		p.bodyBufferPool.Put(buf)
	}

	// Bound the pooled read so Cap never grows past the pool threshold on chunked (-1) bodies.
	limited := io.LimitReader(req.Body, p.maxBodySizeBytesForPool)
	n, readErr := io.Copy(buf, limited)
	if readErr != nil {
		return nil, release, readErr
	}

	if n == p.maxBodySizeBytesForPool {
		// Peek one more byte: if present, body exceeds the pool cap — Put and own the rest.
		var peek [1]byte
		extra, peekErr := req.Body.Read(peek[:])
		if peekErr != nil && peekErr != io.EOF {
			return nil, release, peekErr
		}
		if extra > 0 {
			prefix := append([]byte(nil), buf.Bytes()...)
			release()
			rest, restErr := io.ReadAll(req.Body)
			if restErr != nil {
				return nil, nil, restErr
			}
			owned := make([]byte, 0, len(prefix)+extra+len(rest))
			owned = append(owned, prefix...)
			owned = append(owned, peek[0])
			owned = append(owned, rest...)
			return owned, nil, nil
		}
	}

	// Copy out before Put so sidecar/next never alias a pooled buffer (Yaegi-safe).
	ownedBody := append([]byte(nil), buf.Bytes()...)
	release()
	return ownedBody, nil, nil
}
