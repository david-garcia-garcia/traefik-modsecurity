package modsecurity

import (
	"bytes"
	"io"
	"net/http"
	"sync"
)

// newBodyBufferPool returns a pool of bytes.Buffer for inbound body reads.
func newBodyBufferPool() *sync.Pool {
	return &sync.Pool{
		New: func() interface{} {
			return new(bytes.Buffer)
		},
	}
}

// readInboundBody copies req.Body for the sidecar and next.
// Known length uses this Plugin core's pool only under the pool cap; -1 (unknown) still pools the read.
// The caller must defer release when it is non-nil so Put happens after ServeHTTP
// (including next): buf.Bytes() aliases the pooled array.
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
	release = func() {
		if int64(buf.Cap()) <= p.maxBodySizeBytesForPool {
			p.bodyBufferPool.Put(buf)
		}
	}

	if _, readErr := io.Copy(buf, req.Body); readErr != nil {
		return nil, release, readErr
	}
	return buf.Bytes(), release, nil
}
