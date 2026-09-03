# Go http.MaxBytesReader

Official docs: `MaxBytesReader` limits an incoming request body. A Read beyond the limit returns a non-nil `*http.MaxBytesError` (`Error()` is `http: request body too large`). Negative `n` is treated as `0`.

A limit of `0` therefore rejects the first byte of any non-empty body. `io.ReadAll` / `io.Copy` on a login-sized POST wrapped with `MaxBytesReader(w, body, 0)` yields `*http.MaxBytesError` with `Limit == 0`. That is the mechanism behind acouvreur/traefik-modsecurity-plugin#9 when the handler left the cap at `0`.

Owner: [net/http MaxBytesReader](https://pkg.go.dev/net/http#MaxBytesReader) and [request.go](https://go.dev/src/net/http/request.go) (`if n < 0 { n = 0 }`).

Extracts: `.sources/pkg-go-dev-net-http-maxbytesreader.md`, `.sources/go-src-net-http-request-maxbytesreader.md`

## This product

`readInboundBody` (`pkg/modsecurity/body.go`) calls `MaxBytesReader` only when `p.maxBodySizeBytes > 0`. `Prepare` remaps omitted and explicit `0` to the CreateConfig default (8 MiB) so a Yaegi-omit path does not install a zero limit. Usage: `knowledge/devdocs/core_plugin_middleware.md`.
