package modsecurity

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

var benchBodySizes = []struct {
	name string
	size int
}{
	{"4KB", 4 << 10},
	{"64KB", 64 << 10},
	{"1MB", 1 << 20},
}

func benchPayload(size int) []byte {
	return bytes.Repeat([]byte("x"), size)
}

func benchReadAllInboundBody(maxBody int64, payload []byte) ([]byte, error) {
	req := httptest.NewRequest(http.MethodPost, "http://example/upload", bytes.NewReader(payload))
	req.ContentLength = int64(len(payload))
	rec := httptest.NewRecorder()
	if maxBody > 0 {
		req.Body = http.MaxBytesReader(rec, req.Body, maxBody)
	}
	return io.ReadAll(req.Body)
}

func benchPooledCopyOutInboundBody(pool *sync.Pool, maxBody, poolCap int64, payload []byte) ([]byte, error) {
	req := httptest.NewRequest(http.MethodPost, "http://example/upload", bytes.NewReader(payload))
	req.ContentLength = int64(len(payload))
	rec := httptest.NewRecorder()
	if maxBody > 0 {
		req.Body = http.MaxBytesReader(rec, req.Body, maxBody)
	}

	usePool := true
	if req.ContentLength >= 0 {
		usePool = req.ContentLength <= poolCap
	}
	if !usePool {
		return io.ReadAll(req.Body)
	}

	buf := pool.Get().(*bytes.Buffer)
	buf.Reset()
	defer func() {
		if int64(buf.Cap()) <= poolCap {
			pool.Put(buf)
		}
	}()
	if _, err := io.Copy(buf, req.Body); err != nil {
		return nil, err
	}
	return append([]byte(nil), buf.Bytes()...), nil
}

func BenchmarkReadInboundBody_ReadAll(b *testing.B) {
	const maxBody = 8 << 20
	for _, tc := range benchBodySizes {
		payload := benchPayload(tc.size)
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(tc.size))
			for i := 0; i < b.N; i++ {
				if _, err := benchReadAllInboundBody(maxBody, payload); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkReadInboundBody_PooledCopyOut(b *testing.B) {
	const maxBody = 8 << 20
	const poolCap = 5 << 20
	pool := &sync.Pool{New: func() any { return new(bytes.Buffer) }}
	for _, tc := range benchBodySizes {
		payload := benchPayload(tc.size)
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(tc.size))
			for i := 0; i < b.N; i++ {
				if _, err := benchPooledCopyOutInboundBody(pool, maxBody, poolCap, payload); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
