---
url: https://github.com/golang/go/blob/69801b25b9624c3a678ef87d30771861e7bba51f/src/net/http/httputil/reverseproxy.go
title: httputil reverseproxy.go X-Forwarded-For and hop headers
fetched: 2026-09-01
authority: source
ref: golang/go@69801b25b9624c3a678ef87d30771861e7bba51f:src/net/http/httputil/reverseproxy.go
---

ServeHTTP: `outreq := req.Clone(ctx)` (copies inbound Host field).

hopHeaders: Connection, Proxy-Connection, Keep-Alive, Proxy-Authenticate, Proxy-Authorization, Te, Trailer, Transfer-Encoding, Upgrade. Host is not present. removeHopByHopHeaders also deletes names listed in Connection.

NewSingleHostReverseProxy Director only calls rewriteRequestURL (scheme/host/path/query). It does not assign req.Host.

SetURL: rewriteRequestURL then `r.Out.Host = ""`.

SetXForwarded:

```
clientIP, _, err := net.SplitHostPort(r.In.RemoteAddr)
if err == nil {
    prior := r.Out.Header["X-Forwarded-For"]
    if len(prior) > 0 {
        clientIP = strings.Join(prior, ", ") + ", " + clientIP
    }
    r.Out.Header.Set("X-Forwarded-For", clientIP)
} else {
    r.Out.Header.Del("X-Forwarded-For")
}
r.Out.Header.Set("X-Forwarded-Host", r.In.Host)
// Proto from r.In.TLS == nil
```

Director branch (else of Rewrite):

```
if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
    prior, ok := outreq.Header["X-Forwarded-For"]
    omit := ok && prior == nil
    if len(prior) > 0 {
        clientIP = strings.Join(prior, ", ") + ", " + clientIP
    }
    if !omit {
        outreq.Header.Set("X-Forwarded-For", clientIP)
    }
}
```

Rewrite branch deletes Forwarded, X-Forwarded-For, X-Forwarded-Host, X-Forwarded-Proto before the hook.

No X-Real-IP / X-Real-Ip identifier in this file.
