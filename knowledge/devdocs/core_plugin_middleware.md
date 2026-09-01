# Middleware

## Language

**Plugin core**:
The shared object for one Traefik middleware name and prepared config. It owns the WAF HTTP client, logger, and optional health tracker.
_Avoid_: singleton, instance (ambiguous with Traefik `New`)

**Route**:
The thin `http.Handler` returned by one Traefik `New`. It holds `next` and a pointer to the Plugin core.
_Avoid_: middleware instance

## Overview

Traefik loads this repo as an HTTP middleware plugin. Export `CreateConfig` and `New` at the module root. Traefik calls `New` per route; this repo reuses one Plugin core while name and prepared config stay the same.

## How to use

- Keep the Traefik catalog fields in `.traefik.yml`: `type: middleware`, `import: github.com/david-garcia-garcia/traefik-modsecurity`.
- Add a config knob on `Config` in `pkg/modsecurity` with a `json` tag and `omitempty`, set the default in `CreateConfig()`, apply zeros in `Prepare()`, then use it from `Plugin.ServeHTTP`.
- Reject an empty `ModSecurityUrl` in `Prepare`. `logLevel` is optional; empty becomes `info`; anything other than `debug|info|warn|error` fails Prepare.
- Keep `New` free of network I/O. Observed: `New` calls `Prepare`, `reclaim.Open`, and `ForRoute`. The first outbound call is `httpClient.Do` in `ServeHTTP`.
- On the pass path, restore `req.Body` when you read it, then call `next.ServeHTTP`. Traefik still needs the body for the backend.
- On a WAF status `>= 400`, copy the WAF response with `forwardResponse` and do not call `next`.
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
