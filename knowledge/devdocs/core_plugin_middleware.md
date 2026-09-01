# Middleware

## Language

**Plugin core**:
The shared object for one Traefik middleware name and prepared config. It owns the WAF HTTP client, logger, and optional health tracker.
_Avoid_: singleton, instance (ambiguous with Traefik `New`)

**Route**:
The thin `http.Handler` returned by one Traefik `New`. It holds `next` and a pointer to the Plugin core.
_Avoid_: middleware instance

**WebSocket handshake**:
An HTTP/1.1 GET whose `Connection` list includes the token `upgrade` and whose `Upgrade` value matches `websocket` (case-insensitive).
_Avoid_: Upgrade header (a lone `Upgrade` is not a handshake)

**Sidecar response**:
The HTTP response from `ModSecurityUrl`. On allow the plugin discards its body; on block it copies status and body to the client and omits hop-by-hop headers and `Server`.
_Avoid_: WAF page (ambiguous with `next`)

## Overview

Traefik loads this repo as an HTTP middleware plugin. Export `CreateConfig` and `New` at the module root. Traefik calls `New` per route; this repo reuses one Plugin core while name and prepared config stay the same.

## How to use

- Keep the Traefik catalog fields in `.traefik.yml`: `type: middleware`, `import: github.com/david-garcia-garcia/traefik-modsecurity`.
- Add a config knob on `Config` in `pkg/modsecurity` with a `json` tag and `omitempty`, set the default in `CreateConfig()`, apply zeros in `Prepare()`, then use it from `Plugin.ServeHTTP`.
- Reject an empty `ModSecurityUrl` in `Prepare`. `logLevel` is optional; empty becomes `info`; anything other than `debug|info|warn|error` fails Prepare.
- Keep `New` free of network I/O. Observed: `New` calls `Prepare`, `reclaim.Open`, and `ForRoute`. The first outbound call is `httpClient.Do` in `ServeHTTP`.
- On the pass path, restore `req.Body` when you read it, drain the sidecar response body (up to 256 KiB) so the shared client can reuse the TCP connection, then call `next.ServeHTTP`. Traefik still needs the request body for the backend. Do not forward the sidecar body to the client.
- On a WAF status `>= 400`, copy status and body with `forwardResponse` and do not call `next`. Do not copy hop-by-hop headers (`Connection`, `Keep-Alive`, `Transfer-Encoding`, `Upgrade`, `Proxy-*`, `Te`, `Trailer`, names listed in `Connection`) or `Server`.
- Log request-path events on the core slog logger (`p.logger.Error` / `Info` / `Debug`), not the global `log` package. Traefik `--log.level` does not reach this plugin.

## Pattern snippet

```go
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if err := modsecurity.Prepare(config, name); err != nil {
		return nil, err
	}
	logger := modsecurity.NewLogger(name, config)
	stored, err := reclaim.Open(ctx, pluginKey(name, config), logger, func() (any, error) {
		return modsecurity.New(name, config, logger)
	})
	if err != nil {
		return nil, err
	}
	return stored.(*modsecurity.Plugin).ForRoute(next)
}
```

## Key files

- `.traefik.yml` — catalog type, import path, `testData`.
- `modsecurity.go` — Yaegi `CreateConfig`, `New`, `Config` alias.
- `pkg/modsecurity/` — `Config`, `Plugin`, `Route`, `ServeHTTP`.
- `docker-compose.local.yml` / `docker-compose.test.yml` — `--experimental.localPlugins` plus bind-mount `.:/plugins-local/src/github.com/david-garcia-garcia/traefik-modsecurity`.
- `docker-compose.yml` — catalog plugin (`--experimental.plugins` + `version=`), not a local mount.

## Gotchas

- A GET WebSocket handshake (`Connection` contains the token `upgrade`, `Upgrade` matches `websocket` case-insensitively) skips the WAF and goes straight to `next` (`isWebsocket` in `pkg/modsecurity/serve.go`). A request that only adds `Upgrade: websocket` is inspected.
- Demo compose pins a released module version; local and test compose load this working tree. Do not mix those flags on one Traefik process.
- Traefik still calls `New` per route. Same middleware name and prepared config share one Plugin core (one WAF pool and one health tracker). A different name or config creates another core.
- A slow `New` blocks Traefik startup: routes stay down until every middleware constructor returns. Keep `New` free of network I/O.
- Closing the sidecar response without reading it (Go 1.26 / Traefik v3.7.12) drops the TCP connection. Drain with `drainSidecarBody` on the allow path. Do not add a config knob for the 256 KiB cap.
- The sidecar error-page body on a block is client-visible. Do not assume rule IDs or matched data stay on the sidecar. Hop-by-hop headers and `Server` are stripped; `Set-Cookie` is not.
