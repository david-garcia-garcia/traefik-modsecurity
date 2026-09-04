# Middleware

## Language

**Plugin core**:
The shared object for one Traefik middleware name and prepared config. It owns the WAF HTTP client, logger, optional health tracker, and body buffer pool.
_Avoid_: singleton, instance (ambiguous with Traefik `New`)

**Route**:
The thin `http.Handler` returned by one Traefik `New`. It holds `next` and a pointer to the Plugin core.
_Avoid_: middleware instance

**Security block**:
A sidecar `3xx` or `4xx` that is copied to the client. The next handler is not called.
_Avoid_: deny (ModSecurity action name)

**WAF failure**:
A transport error talking to the sidecar, or a sidecar `5xx`. Not a security block.
_Avoid_: outage (operator slang)

**WebSocket handshake**:
An HTTP/1.1 GET whose `Connection` list includes the token `upgrade` and whose `Upgrade` value matches `websocket` (case-insensitive). That GET is still inspected. Frames after the backend's 101 are Traefik's tunnel, not this plugin.
_Avoid_: Upgrade header (a lone `Upgrade` is not a handshake); WebSocket skip (this plugin does not skip on those headers)

**Sidecar request**:
The HTTP request `ServeHTTP` builds and sends to `ModSecurityUrl`.
_Avoid_: WAF request (ambiguous with the incoming client request)

**Sidecar response**:
The HTTP response from `ModSecurityUrl`. On allow the plugin discards its body; on block it copies status and body to the client and omits hop-by-hop headers and `Server`.
_Avoid_: WAF page (ambiguous with `next`)

**Status request header**:
The optional request header named by `modSecurityStatusRequestHeader`. Traefik access logs keep it so operators can tell allow (`ok`) from a block (`blocked`) from a broken WAF (`error`) from fail-open (`unhealthy`) from a bypass-rule skip (`bypassrule`). `error` is a WAF communication failure only (sidecar unreachable, sidecar 5xx, cannot build the sidecar request). It is not a response header and it is not an HTTP status code.
_Avoid_: remediation header, WAF response header

**Body buffer pool**:
The reuse pool of `bytes.Buffer` on one Plugin core, used for request bodies whose parsed size is at or under that core's `maxBodySizeBytesForPool`.
_Avoid_: body cache, request buffer (ambiguous with `MaxBytesReader`), process-wide pool

**Denied-verb body**:
A request body whose method is listed in `denyVerbsWithBody`. The plugin rejects that request with HTTP 400.
_Avoid_: ignored-verb body, ignoreBodyForVerbs

**Bypass rule**:
One operator `bypassRules` entry: optional HTTP method and optional path regexp. A match skips the sidecar, body buffering, and denied-verb-body reject, and writes `bypassrule` on the status request header when that name is set.
_Avoid_: router skip (a Traefik router without this middleware)

**WAF base URL**:
The prepared `ModSecurityUrl`: an absolute `http` or `https` origin (scheme + host and optional port) with no path. `ServeHTTP` concatenates it with the request URI.
_Avoid_: sidecar path, WAF endpoint path

**Allow**:
A sidecar HTTP status below 300.
_Avoid_: pass

**Fail mode**:
The operator `failMode` string after Prepare: `open` calls `next` when the WAF cannot inspect; `close` writes empty HTTP 502 and does not call `next`. Default `open`.
_Avoid_: failClosed (boolean)

## Overview

Traefik loads this repo as an HTTP middleware plugin. Export `CreateConfig` and `New` at the module root. Traefik calls `New` per route; this repo reuses one Plugin core while name and prepared config stay the same.

## How to use

- Keep the Traefik catalog fields in `.traefik.yml`: `type: middleware`, `import: github.com/david-garcia-garcia/traefik-modsecurity`.
- Add a config knob on `Config` in `pkg/modsecurity` with a `json` tag and `omitempty`, set the default in `CreateConfig()`, apply zeros in `Prepare()`, then use it from `Plugin.ServeHTTP`.
- Reject an empty `ModSecurityUrl` in `Prepare`. Parse it as an absolute `http`/`https` WAF base URL with a host and no path; trim a lone trailing slash. Reject every numeric config field that is negative. `logLevel` is optional; empty becomes `info`; anything other than `debug|info|warn|error` fails Prepare. `failMode` is optional; empty becomes `open`; anything other than `open|close` fails Prepare.
- Keep `New` free of network I/O. Observed: `New` calls `Prepare`, `reclaim.Open`, and `ForRoute`. The first outbound call is `httpClient.Do` in `ServeHTTP`. Build that sidecar request with `http.NewRequestWithContext(req.Context(), …)` so a client disconnect or Traefik deadline cancels it. `timeoutMillis` still caps the call when the inbound context stays live. The shared WAF client does not follow `Location`; `Do` returns the sidecar's own 3xx.
- After `http.NewRequestWithContext` and the `req.Header` copy, set `proxyReq.Host = req.Host`. Incoming Host is not in the header map. Copy Traefik’s headers as-is. Do not append `req.RemoteAddr` to `X-Forwarded-For`. Do not set `X-Real-IP`.
- After `Do`, a sidecar `3xx` or `4xx` is copied with `forwardResponse`, then `discardSidecarBody`, then return. Allow and 5xx `discardSidecarBody` (256 KiB cap) so the shared client can reuse the TCP connection, then `next` (`failMode` `open`) or empty HTTP 502 (`failMode` `close`). Do not buffer the sidecar body on the allow path. On allow, do not copy sidecar response headers onto the client `ResponseWriter`; `next` writes the headers the client sees (CORS and custom backend headers included). After the inbound body is read, restore `req.Body` once so pass and fail-open both still have it for Traefik.
- Read the inbound body with `readInboundBody` (`pkg/modsecurity/body.go`). Wrap with `http.MaxBytesReader` only when `maxBodySizeBytes > 0`; a leftover handler field `0` must not install a zero-limit reader (that 413s every non-empty POST). The pool is created in `New` on that Plugin core (`p.bodyBufferPool`); do not use a package-level pool. Choose the pool from `req.ContentLength` (not `Header.Get("Content-Length")`). Known length above `maxBodySizeBytesForPool` uses ad-hoc allocation. `-1` (unknown) still uses the pool. After a successful pooled read, copy `buf.Bytes()` into an owned slice and Put the buffer before returning; do not hand `buf.Bytes()` to the sidecar or `next` (`Client.Do` / a RoundTripper may still Read `Request.Body` after `ServeHTTP` returns). Put only when `buf.Cap()` is at or under that cap. On a pooled read error, `readInboundBody` still returns `release` so `ServeHTTP` can Put. When the read returns an error, `ServeHTTP` writes 413 or 502 via `replyInboundBodyReadFailure`.
- When the method is in `denyVerbsWithBody` and the request has a body, return HTTP 400 before the sidecar and before `next`, including when the WAF is already unhealthy. Omitted `denyVerbsWithBody` uses the CreateConfig default list. An explicit empty slice denies nothing. Methods not on the list are inspected and forwarded.
- `bypassRules` is optional. Compile in `pkg/modsecurity/bypass.go` into one regexp per uppercase method (each `pathRegexp` wrapped `(?:…)` and joined with `|`). ServeHTTP does one map lookup then at most one `MatchString` on `req.URL.Path` before denyVerbsWithBody and body read. A match writes `bypassrule` when the status header name is set, then `next`. Invalid `pathRegexp` fails Prepare. MatchString is unanchored (`health` matches `/unhealthy`; `/health` matches `/healthz` and `/index.php/health`). Do not insert `^` / `\A` around the operator pattern. Prefix or exact matching is the operator’s (`^/admin/`, `^/health$`). The match subject is percent-decoded `req.URL.Path` and is not slash-normalized.
- On a sidecar `3xx` or `4xx` (security block), copy status and body with `forwardResponse` and do not call `next`. Do not copy hop-by-hop headers (`Connection`, `Keep-Alive`, `Transfer-Encoding`, `Upgrade`, `Proxy-*`, `Te`, `Trailer`, names listed in `Connection`) or `Server`. When `modSecurityStatusRequestHeader` is set, write `blocked`. Do not write an HTTP status code on that header.
- On a local body-too-large reject, write `blocked` on that header and return 413. On every sidecar `httpClient.Do` failure, every sidecar `5xx`, and when the forwarded sidecar request cannot be built, write `error` even when no health tracker exists. Do not write `cannotforward`. Do not write `error` for an inbound body-read failure other than oversize (that path is HTTP 502 with the header left unset after Del). Keep `unhealthy` for an already-down tracker. On sidecar allow (status below 300), write `ok`. Write `bypassrule` on a bypass-rule match. When the header name is set, `Del` it at the start of `ServeHTTP` then `Set` the WAF outcome. Leave it unset on inbound `Canceled` and on a non-413 inbound body-read failure.
- Log client-fault rejections (`denyVerbsWithBody` body, body too large) at `Warn`. Log infrastructure failures (cannot read the body for another reason, cannot reach ModSecurity) at `Error`. Use the core slog logger, not the global `log` package. Traefik `--log.level` does not reach this plugin.

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
- `pkg/modsecurity/` — `Config`, `Plugin`, `Route`, `ServeHTTP`, `readInboundBody`, `compileBypassByMethod`.
- `docker-compose.local.yml` / `docker-compose.test.yml` — `--experimental.localPlugins` plus bind-mount `.:/plugins-local/src/github.com/david-garcia-garcia/traefik-modsecurity`.
- `docker-compose.yml` — catalog plugin (`--experimental.plugins` + `version=`), not a local mount.

## Gotchas

- A GET WebSocket handshake is inspected like any other GET. After sidecar allow, `next` runs and Traefik tunnels frames; this plugin does not see those frames. A `bypassRules` match is the operator skip (writes `bypassrule`). Do not reconstruct “this is a WebSocket” from client `Upgrade` headers.
- Demo compose pins a released module version; local and test compose load this working tree. Do not mix those flags on one Traefik process.
- Traefik still calls `New` per route. Same middleware name and prepared config share one Plugin core (one WAF pool and one health tracker). A different name or config creates another core.
- A slow `New` blocks Traefik startup: routes stay down until every middleware constructor returns. Keep `New` free of network I/O.
- `Prepare` fails construction on a negative numeric field and on a `ModSecurityUrl` that is not a WAF base URL. A trailing slash is trimmed so concatenation does not produce `//path`.
- The sidecar request uses `req.Context()`. A client disconnect (`Canceled`) is not a WAF health failure. An inbound request deadline while waiting on the sidecar, and `timeoutMillis` (`Client.Timeout`), still are.
- ModSecurity `SecRequestBodyLimit` / `SecRequestBodyNoFilesLimit` reject with **413**, not 5xx. That sidecar 413 is a security-class block (`forwardResponse`), not a WAF failure. This plugin’s own `maxBodySizeBytes` also returns 413 before the sidecar.
- Closing the sidecar response without reading it (Go 1.26 / Traefik v3.7.12) drops the TCP connection. `discardSidecarBody` after a 3xx or 4xx copy (then return) and before allow/`next` or 5xx fail-open. Do not add a config knob for the 256 KiB cap.
- Do not decide the body buffer pool from the `Content-Length` header. net/http deletes that header on chunked HTTP/1, so `Header.Get` is empty while `req.ContentLength` is `-1`. A grown pooled buffer must not be Put back when `Cap()` exceeds `maxBodySizeBytesForPool`. After a successful pooled read, copy the unread bytes then Put; do not return `buf.Bytes()` to `ServeHTTP`. Distinct Plugin cores must not share a pool; routes that share a core share that core's pool.
- The sidecar error-page body on a block is client-visible. Do not assume rule IDs or matched data stay on the sidecar. Hop-by-hop headers and `Server` are stripped; `Set-Cookie` is not.
