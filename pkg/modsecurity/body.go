package modsecurity

import (
	"bytes"
	"io"
	"net/http"
	"sync"
)

// bodyBufferPool reuses buffers for request bodies under the pool threshold.
// The pointer lets tests swap the pool without copying sync.Pool.
var bodyBufferPool = &sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

// readInboundBody copies req.Body for the sidecar and next.
// Known length uses the pool only under the pool cap; -1 (unknown) still pools the read.
// The caller must defer release when it is non-nil so Put happens after ServeHTTP
// (including next): buf.Bytes() aliases the pooled array.
func (p *Plugin) readInboundBody(rw http.ResponseWriter, req *http.Request) (body []byte, release func(), ok bool) {
	if p.maxBodySizeBytes > 0 {
		req.Body = http.MaxBytesReader(rw, req.Body, p.maxBodySizeBytes)
	}

	usePool := true
	if req.ContentLength >= 0 {
		usePool = req.ContentLength <= p.maxBodySizeBytesForPool
	}

	if !usePool {
		largeBody, err := io.ReadAll(req.Body)
		if err != nil {
			p.replyInboundBodyReadFailure(rw, req, err)
			return nil, nil, false
		}
		return largeBody, nil, true
	}

	buf := bodyBufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	release = func() {
		if int64(buf.Cap()) <= p.maxBodySizeBytesForPool {
			bodyBufferPool.Put(buf)
		}
	}

	if _, err := io.Copy(buf, req.Body); err != nil {
		p.replyInboundBodyReadFailure(rw, req, err)
		return nil, release, false
	}
	return buf.Bytes(), release, true
}

// replyInboundBodyReadFailure writes 413 for MaxBytesError or 502 for any other read error.
func (p *Plugin) replyInboundBodyReadFailure(rw http.ResponseWriter, req *http.Request, err error) {
	if maxBytesErr, ok := err.(*http.MaxBytesError); ok {
		p.logger.Error("request body too large", "limit", maxBytesErr.Limit, "maxBodySizeBytes", p.maxBodySizeBytes)
		if p.modSecurityStatusRequestHeader != "" {
			req.Header.Set(p.modSecurityStatusRequestHeader, "blocked")
		}
		http.Error(rw, "Request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	p.logger.Error("fail to read incoming request", "error", err)
	http.Error(rw, "", http.StatusBadGateway)
}
