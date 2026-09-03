## Why

On `main`, allow-path tests assert status and body only. [acouvreur/traefik-modsecurity-plugin#29](https://github.com/acouvreur/traefik-modsecurity-plugin/issues/29) reports lost backend CORS headers after a sidecar allow. Native Go already hands the original `ResponseWriter` to `next` and does not overlay sidecar headers; without a durable test, a later `ServeHTTP` change could drop those headers unnoticed.

## What Changes

- Add `pkg/modsecurity/upstream_issue_29_test.go`: WAF 200, `next` sets CORS + `X-Backend`, assert those headers on `httptest.Server` and `httptest.Recorder` for GET / OPTIONS / POST, and assert sidecar headers do not leak.
- Fold one requirement into `core_plugin_middleware_sidecar-response`: allow-path client headers are `next`'s, not the sidecar's.
- One usage sentence on `knowledge/devdocs/core_plugin_middleware.md`.
- Do **not** change `ServeHTTP`. Not **BREAKING**.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_middleware_sidecar-response`: allow path keeps `next` response headers; sidecar response headers MUST NOT overlay the client.

## Impact

- Tests: `pkg/modsecurity/upstream_issue_29_test.go` (new).
- Spec: `openspec/specs/core_plugin_middleware_sidecar-response/spec.md` (requirement add).
- Usage: `knowledge/devdocs/core_plugin_middleware.md` (one sentence).
- Runtime / config / Yaegi wrapping: unchanged.
