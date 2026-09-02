# Request.Host

Go `net/http` keeps inbound Host on `Request.Host`, not in `Request.Header` (HTTP/1). `http.NewRequest` fills `Host` from the URL. Copying `Header` does not carry Host onto the wire.

Pinned: Go 1.25.6 (`golang/go@69801b25b9624c3a678ef87d30771861e7bba51f`). Read from local GOROOT; no temp clone.

## Inbound: use `Request.Host`

For a server-side request, `Host` is the host on which the URL is sought. HTTP/1 (RFC 7230 §5.4): the `Host` header, or the host in an absolute-form request-target. HTTP/2: the `:authority` pseudo-header. It may be `host:port`.

Official docs: the inbound Host header is promoted onto `Request.Host` and **removed from the `Header` map**. That matches HTTP/1. HTTP/2 in this pin sets `Request.Host` from `:authority` and does not delete a regular `Host` header if the client sent one.

Always read `req.Host`. Do not use `Header.Get("Host")` as the inbound host.

Owner: [Request.Header](https://pkg.go.dev/net/http@go1.25.6#Request) and [Request.Host](https://pkg.go.dev/net/http@go1.25.6#Request).

Extract: `.sources/pkg-go-dev-net-http-request.md`

HTTP/1 implementation: `readRequest` sets `req.Host` from `req.URL.Host`, or from `req.Header.get("Host")` when the request-target has no host. `ReadRequest` and the HTTP/1 server then `delete(req.Header, "Host")`.

Owner: `golang/go@69801b25b9624c3a678ef87d30771861e7bba51f:src/net/http/request.go` (`readRequest`, `ReadRequest`) and `src/net/http/server.go`.

Extract: `.sources/golang-go-request.go.md` (also `.sources/request.go.md`)

HTTP/2 implementation: regular fields are copied into `Header`; if `:authority` is empty, Authority falls back to `header.Get("Host")`; `Request.Host = rp.Authority`. `NewServerRequest` does not delete `Host` from the map. Official “removed from the Header map” is the HTTP/1 path; follow source for HTTP/2.

Owner: `golang/go@69801b25b9624c3a678ef87d30771861e7bba51f:src/net/http/h2_bundle.go` and `src/net/http/internal/httpcommon/httpcommon.go`.

Extract: `.sources/golang-go-h2_bundle.go.md`

## Outbound: `NewRequest` sets `Host` from the URL

`NewRequest` wraps `NewRequestWithContext`. After `url.Parse` and `removeEmptyPort`, the new request is:

```
Host: u.Host
Header: make(Header)  // empty
```

So `http.NewRequest(method, wafUrl+path, body)` sets `proxyReq.Host` to the **sidecar URL host**, not the inbound client Host.

The official `NewRequest` / `NewRequestWithContext` comments do not name this assignment. The field comment does: for client requests, `Host` optionally overrides the Host header to send; if empty, `Request.Write` uses `URL.Host`.

Owner (assignment): `golang/go@69801b25b9624c3a678ef87d30771861e7bba51f:src/net/http/request.go` (`NewRequestWithContext`).

Owner (Write preference): [Request.Host](https://pkg.go.dev/net/http@go1.25.6#Request) and [Request.Write](https://pkg.go.dev/net/http@go1.25.6#Request.Write) / [Request.WriteProxy](https://pkg.go.dev/net/http@go1.25.6#Request.WriteProxy).

## Copying `Header` does not send Host

Two independent facts:

1. HTTP/1 inbound `Header` no longer contains `Host` after promotion, so a Header copy cannot restore inbound Host on that path. HTTP/2 may still have a regular `Host` entry; Write still ignores it (next point).
2. `Request.Write` does **not** use `Header` values for Host. Official: “Header values for Host, Content-Length, Transfer-Encoding, and Trailer are not used; these are derived from other Request fields.” Write emits `Host: %s` from `r.Host`, or `r.URL.Host` if `r.Host` is empty, and skips `"Host"` when writing the `Header` map.

To send the inbound Host to a sidecar built with `NewRequest`, assign `proxyReq.Host = req.Host`. Putting `"Host"` into `proxyReq.Header` is ignored on the wire.

Owner: [Request.Write](https://pkg.go.dev/net/http@go1.25.6#Request.Write).

Implementation: `request.go` `reqWriteExcludeHeader["Host"]` and `write`.
