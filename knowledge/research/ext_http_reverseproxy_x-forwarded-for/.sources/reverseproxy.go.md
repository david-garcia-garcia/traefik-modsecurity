---
url: https://github.com/golang/go/blob/go1.25.6/src/net/http/httputil/reverseproxy.go
title: src/net/http/httputil/reverseproxy.go
fetched: 2026-09-01
authority: source
ref: golang/go@go1.25.6:src/net/http/httputil/reverseproxy.go
---

Inspected from the local toolchain (`go1.25.6`). Compared `https://raw.githubusercontent.com/golang/go/go1.26.0/src/net/http/httputil/reverseproxy.go` (`golang/go@go1.26.0`): SetXForwarded and Director XFF blocks are the same.

ServeHTTP: `outreq := req.Clone(ctx)` then Director or Rewrite.

SetXForwarded:

- `clientIP, _, err := net.SplitHostPort(r.In.RemoteAddr)`
- err == nil: `prior := r.Out.Header["X-Forwarded-For"]`; if len(prior) > 0, `clientIP = strings.Join(prior, ", ") + ", " + clientIP`; Set X-Forwarded-For
- err != nil: Del X-Forwarded-For
- Set X-Forwarded-Host to `r.In.Host`
- Set X-Forwarded-Proto to http if `r.In.TLS == nil` else https

Rewrite branch: Del Forwarded, X-Forwarded-For, X-Forwarded-Host, X-Forwarded-Proto, then call Rewrite.

Director branch (else):

```
if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
    prior, ok := outreq.Header["X-Forwarded-For"]
    omit := ok && prior == nil // Issue 38079
    if len(prior) > 0 {
        clientIP = strings.Join(prior, ", ") + ", " + clientIP
    }
    if !omit {
        outreq.Header.Set("X-Forwarded-For", clientIP)
    }
}
```

No X-Forwarded-Host / X-Forwarded-Proto in this branch. Failed SplitHostPort: no Set, no Del.
