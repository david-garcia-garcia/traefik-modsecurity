# HTTP/1 client response-body reuse

An HTTP/1.1 keep-alive connection cannot start the next request until the previous response body is read to EOF. Go's `net/http` Transport puts the connection in the idle pool only then.

## Close without EOF (Go 1.26)

If `Response.Body` is not both read to EOF and closed, the Transport may not reuse the TCP connection. `Close` before EOF runs the early-close path and skips `tryPutIdleConn`.

Owner: [net/http Client.Do](https://pkg.go.dev/net/http#Client.Do) and [Response.Body](https://pkg.go.dev/net/http#Response).

Extract: `.sources/pkg-go-dev-net-http.md`

Pinned implementation: `golang.org/toolchain@go1.26.7` `src/net/http/transport.go` `bodyEOFSignal.Close` / `readLoop`.

## Auto-drain on Close (Go 1.27)

Go 1.27 drains unread HTTP/1 response bodies on `Close`, up to 256 KiB or 50 ms. Traefik v3.7.12 is Go 1.26, so Yaegi plugins do not get this. An explicit bounded drain is still correct on 1.27.

Owner: [golang/go#77370](https://github.com/golang/go/issues/77370).

Extract: `.sources/golang-go-77370.md`

## This product

Allow, 5xx, and leftover-after-4xx-copy drain live in `pkg/modsecurity/serve.go` (`discardSidecarBody`, 256 KiB). Usage: `knowledge/devdocs/core_plugin_middleware.md`.
