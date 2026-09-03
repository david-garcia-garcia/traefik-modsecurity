## Why

Upstream [acouvreur/traefik-modsecurity-plugin#13](https://github.com/acouvreur/traefik-modsecurity-plugin/issues/13) reports Authelia login failing with access-log `POST /api/firstfactor` 405 after WAF attach. This plugin does not invent 405; without a unit pin, that claim can regress silently.

## What Changes

- Add a Go unit test that posts to `/api/firstfactor` with portal Host and Traefik identity headers: allow sidecar calls `next` (not 405); sidecar 405 is copied and `next` is skipped.
- Fold two scenarios onto existing sidecar specs (405 copy; Authelia-shaped POST Host/XFF).
- No runtime change. No Authelia/ForwardAuth compose. No 405 knob.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_middleware_sidecar-response`: pin that a sidecar 405 is copied as a block (client 405, `next` skipped) and that an allow on `POST /api/firstfactor` is not 405.
- `core_plugin_middleware_sidecar-request`: pin that the Authelia-shaped login POST forwards inbound Host and leftover `X-Forwarded-For` / `X-Real-Ip` as-is (no `RemoteAddr` hop).

## Impact

- Tests: `pkg/modsecurity/upstream_issue_13_test.go`
- Specs: delta folders under this change for the two modified capabilities
- Runtime, compose, README: none
