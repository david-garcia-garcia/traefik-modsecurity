# Request context cancellation

Go's `http.NewRequest` wraps `NewRequestWithContext` with `context.Background()`. An outbound request built that way is not canceled when the inbound handler's `req.Context()` is canceled.

`http.NewRequestWithContext` binds the given context. For an outgoing client request, that context controls the entire lifetime: obtaining a connection, sending the request, and reading the response headers and body. `Client.Do` then returns an error when that context is done (`context.Canceled` or `context.DeadlineExceeded`).

`http.Client.Timeout` still applies on its own. Binding the inbound request context does not remove the client-level timeout; the effective stop is whichever fires first.

`Client.Timeout` cancels the transport “as if the Request's Context ended.” The parent context passed to `NewRequestWithContext` is not canceled. `Do` then returns a `*url.Error` whose `Timeout()` is true and that unwraps to `context.DeadlineExceeded`, while `req.Context().Err()` stays nil. An inbound cancel unwraps to `context.Canceled` and `req.Context().Err()` is `context.Canceled`.

Do not treat `errors.Is(doErr, context.DeadlineExceeded)` as “inbound deadline.” That is also true for `Client.Timeout`. The owner of “inbound is done” is `req.Context().Err()`.

Owner: [net/http NewRequest](https://pkg.go.dev/net/http#NewRequest), [NewRequestWithContext](https://pkg.go.dev/net/http#NewRequestWithContext), and [Client.Timeout](https://pkg.go.dev/net/http#Client.Timeout).

Measured: `go test` probe on this tree (2026-09-02). Client timeout: inbound Err nil, `errors.Is(doErr, context.DeadlineExceeded)` true, error text includes `Client.Timeout exceeded while awaiting headers`. Inbound cancel: inbound Err `context canceled`, `errors.Is(doErr, context.Canceled)` true.

Extract: `.sources/pkg-go-dev-net-http-newrequest.md`, `.sources/pkg-go-dev-net-http-client-timeout.md`

## This product

`pkg/modsecurity/serve.go` builds the sidecar request with `http.NewRequestWithContext(req.Context(), ...)`. Usage: `knowledge/devdocs/core_plugin_middleware.md`.
