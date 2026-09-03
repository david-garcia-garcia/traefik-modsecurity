---
url: https://go.dev/src/net/http/request.go
title: net/http MaxBytesReader negative-as-zero
fetched: 2026-09-03
authority: source
ref: go.dev/src/net/http/request.go
---

if n < 0 { // Treat negative limits as equivalent to 0.
	n = 0
}

MaxBytesError carries Limit int64. A Read that exceeds remaining n returns that error. With n == 0, the first non-empty Read is beyond the limit.
