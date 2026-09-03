---
url: https://github.com/golang/go/blob/e3336a22ad3f0a90bd252c95d8b5544e02674205/src/net/http/h2_bundle.go
title: net/http h2_bundle.go incoming request ContentLength
fetched: 2026-09-01
authority: source
ref: golang/go@e3336a22ad3f0a90bd252c95d8b5544e02674205:src/net/http/h2_bundle.go
---

HTTP/2 incoming (bodyOpen := !HEADERS END_STREAM):

- If Header["Content-Length"] is present: ParseUint of the first value, 10, 63 bits. Success → ContentLength = that int64. Parse error → ContentLength = 0. Header map is not deleted.
- Else: ContentLength = -1.

No Transfer-Encoding path. Missing Content-Length on an open body is unknown (-1), unlike HTTP/1 fixLength which defaults a request with neither TE nor CL to 0.
