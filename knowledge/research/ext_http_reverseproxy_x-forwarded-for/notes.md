# ReverseProxy X-Forwarded-For

`net/http/httputil.ReverseProxy` (Director path, including `NewSingleHostReverseProxy`) appends the peer IP from `RemoteAddr` to `X-Forwarded-For`. It does not treat Host as hop-by-hop. It does not set `X-Real-IP`.

Pinned: Go 1.25.6 (`golang/go@69801b25b9624c3a678ef87d30771861e7bba51f`). Read from local GOROOT; no temp clone.

## Director default: append peer IP

When `Director` is set (not `Rewrite`), after hop-by-hop stripping:

1. `clientIP, _, err := net.SplitHostPort(req.RemoteAddr)`
2. If `err != nil`, leave `X-Forwarded-For` unchanged.
3. If the outbound map has key `"X-Forwarded-For"` with a **nil** value, do not write the header (Issue 38079).
4. Else if prior values exist: `clientIP = strings.Join(prior, ", ") + ", " + clientIP` (fold multiple header values, then append this hop).
5. `outreq.Header.Set("X-Forwarded-For", clientIP)`

Official: “By default, the X-Forwarded-For header is set to the value of the client IP address. If an X-Forwarded-For header already exists, the client IP is appended to the existing values.” Nil-value special case is documented on `Director`.

Owner: [ReverseProxy.Director](https://pkg.go.dev/net/http/httputil@go1.25.6#ReverseProxy).

Extract: `.sources/pkg-go-dev-httputil-reverseproxy.md`

Implementation: `golang/go@69801b25b9624c3a678ef87d30771861e7bba51f:src/net/http/httputil/reverseproxy.go` (`ServeHTTP` Director branch).

Extract: `.sources/golang-go-reverseproxy.go.md`

`Rewrite` is different: it **deletes** `Forwarded`, `X-Forwarded-For`, `X-Forwarded-Host`, and `X-Forwarded-Proto` before the hook. `SetXForwarded` then sets XFF from `In.RemoteAddr` (appending only to values already on `Out`), plus `X-Forwarded-Host` from `In.Host` and `X-Forwarded-Proto` from `In.TLS`. If `SplitHostPort` fails, `SetXForwarded` **deletes** XFF. Official docs say to copy inbound XFF onto `Out` first to match Director.

## IPv6 and `RemoteAddr`

`Request.RemoteAddr` has no defined format in general. The `net/http` server sets it to an `"IP:port"` string (`rwc.RemoteAddr().String()`).

`net.TCPAddr.String` uses `JoinHostPort`. `JoinHostPort` wraps a host that contains `:` in brackets: `[2001:db8::1]:80`.

`SplitHostPort` accepts `"host:port"`, `"host%zone:port"`, `"[host]:port"`, `"[host%zone]:port"`. A literal IPv6 address **must** be bracketed. The returned host **drops the brackets**: `"[::1]:80"` → host `"::1"`; `"[fe80::1%lo0]:80"` → host `"fe80::1%lo0"`. That unbracketed host is what ReverseProxy writes into XFF.

Owner: [Request.RemoteAddr](https://pkg.go.dev/net/http@go1.25.6#Request), [SplitHostPort](https://pkg.go.dev/net@go1.25.6#SplitHostPort), [JoinHostPort](https://pkg.go.dev/net@go1.25.6#JoinHostPort).

Extract: `.sources/pkg-go-dev-net-splithostport.md`

Implementation: `golang/go@69801b25b9624c3a678ef87d30771861e7bba51f:src/net/ipsock.go` (`SplitHostPort`, `JoinHostPort`); `src/net/tcpsock.go` (`TCPAddr.String`); `src/net/http/server.go` (`c.remoteAddr = ra.String()`).

Extract: `.sources/golang-go-ipsock.go.md`

## Host is not hop-by-hop

Hop-by-hop headers ReverseProxy removes: Connection, Proxy-Connection, Keep-Alive, Proxy-Authenticate, Proxy-Authorization, TE, Trailer, Transfer-Encoding, Upgrade (plus names listed in `Connection`). **Host is not in that list.**

`ServeHTTP` starts from `req.Clone(ctx)`, which copies the inbound `Host` field. `NewSingleHostReverseProxy` rewrites `URL` only and “does not rewrite the Host header.” `SetURL` (Rewrite path) clears `Out.Host` so Write uses the target `URL.Host`, unless the hook restores `r.Out.Host = r.In.Host`.

Owner: [ReverseProxy](https://pkg.go.dev/net/http/httputil@go1.25.6#ReverseProxy) hop-by-hop paragraph; [NewSingleHostReverseProxy](https://pkg.go.dev/net/http/httputil@go1.25.6#NewSingleHostReverseProxy); [ProxyRequest.SetURL](https://pkg.go.dev/net/http/httputil@go1.25.6#ProxyRequest.SetURL).

Related inbound Host field: `knowledge/research/ext_http_request_host/`.

## No `X-Real-IP`

Official ReverseProxy / SetXForwarded docs name `X-Forwarded-For`, `X-Forwarded-Host`, and `X-Forwarded-Proto` only. `reverseproxy.go` in this pin has no `X-Real-IP` / `X-Real-Ip` identifier. ReverseProxy does not set `X-Real-IP`.

Owner: [SetXForwarded](https://pkg.go.dev/net/http/httputil@go1.25.6#ProxyRequest.SetXForwarded) and `golang/go@69801b25b9624c3a678ef87d30771861e7bba51f:src/net/http/httputil/reverseproxy.go`.
