# Go http.Client Timeout

Official docs: `Client.Timeout` is a time limit for the whole request (connect, redirects, response body). A Timeout of zero means no timeout.

`Client.deadline` applies a deadline only when `Timeout > 0`. Zero and negative values both yield a zero `time.Time`, so the client does not cancel the request. A negative Timeout does not fail the request instantly.

Owner: [net/http Client](https://pkg.go.dev/net/http#Client) and [client.go deadline](https://go.dev/src/net/http/client.go).

Extracts: `.sources/pkg-go-dev-net-http-client.md`, `.sources/go-src-net-http-client-deadline.md`

## This product

`New` sets `http.Client.Timeout` from `timeoutMillis` whenever the value is not zero. A negative prepared value therefore disables the client deadline (same as zero), not an instant fail. `Prepare` should reject negatives so that typo cannot drop the limit. Usage: `knowledge/devdocs/core_plugin_middleware.md`.
