## Why

[acouvreur/traefik-modsecurity-plugin#11](https://github.com/acouvreur/traefik-modsecurity-plugin/issues/11) reports a large non-file POST becoming a client HTTP 500. This tree already maps plugin oversize to 413 `blocked`, sidecar 413 to a copied block, and sidecar 5xx to 502 `error`, but no committed test names that issue or uses a large form POST as the fixture.

## What Changes

- Add `pkg/modsecurity/upstream_issue_11_test.go`: a 6 MiB `application/x-www-form-urlencoded` POST that asserts never client 500, and the three mapped statuses.
- Fold one pin scenario onto `core_plugin_middleware_waf-status` so the composition is a named requirement, not only scattered existing cases.
- No production code. No status-mapping change. No file vs non-file plugin distinction.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_middleware_waf-status`: add a scenario that a large non-file body never becomes a forwarded client 500 (plugin 413 / sidecar 413 / sidecar 5xx → 502).

## Impact

- Tests: `pkg/modsecurity/upstream_issue_11_test.go`
- Spec: `openspec/specs/core_plugin_middleware_waf-status/spec.md` (delta only)
- Runtime plugin, config keys, and sidecar engine limits: unchanged
