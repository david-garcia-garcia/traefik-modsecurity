# Request context cancellation

Go's `http.NewRequest` wraps `NewRequestWithContext` with `context.Background()`. An outbound request built that way is not canceled when the inbound handler's `req.Context()` is canceled.

`http.NewRequestWithContext` binds the given context. For an outgoing client request, that context controls the entire lifetime: obtaining a connection, sending the request, and reading the response headers and body. `Client.Do` then returns an error when that context is done (`context.Canceled` or `context.DeadlineExceeded`).

`http.Client.Timeout` still applies on its own. Binding the inbound request context does not remove the client-level timeout; the effective stop is whichever fires first.

Owner: [net/http NewRequest](https://pkg.go.dev/net/http#NewRequest) and [NewRequestWithContext](https://pkg.go.dev/net/http#NewRequestWithContext).

Extract: `.sources/pkg-go-dev-net-http-newrequest.md`

## This product

`pkg/modsecurity/serve.go` builds the sidecar request with `http.NewRequestWithContext(req.Context(), ...)`. Usage: `knowledge/devdocs/core_plugin_middleware.md`.
