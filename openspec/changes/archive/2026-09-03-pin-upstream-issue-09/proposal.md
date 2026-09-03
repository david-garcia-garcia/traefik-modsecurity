## Why

Upstream acouvreur/traefik-modsecurity-plugin#9 showed that `http.MaxBytesReader` with limit `0` 413s every non-empty POST, including a login form. This tree already remaps omitted/`0` `maxBodySizeBytes` to 8 MiB and skips the wrapper when the handler field is `0`, but `origin/main` has no test that pins those outcomes. Without the pin, a later wiring change can reintroduce the 1.2.0 bug and CI will not catch it.

## What Changes

- Add Go tests in `pkg/modsecurity/upstream_issue_09_test.go` that a login-sized POST is 200 when `maxBodySizeBytes` is omitted or `0`, and that a leftover handler field `0` does not 413.
- Add spec `core_plugin_middleware_maxbodysize` for that inbound body-cap pin.
- Do not change CreateConfig, Prepare remapping, or `readInboundBody` product behavior.
- README / default-docs drift stays out of scope (#20).

## Capabilities

### New Capabilities
- `core_plugin_middleware_maxbodysize`: Inbound `maxBodySizeBytes` after Prepare (omitted/`0` → 8 MiB) and the rule that `MaxBytesReader` is applied only when the handler limit is greater than zero.

### Modified Capabilities

## Impact

- Tests: `pkg/modsecurity/upstream_issue_09_test.go`
- Spec: `openspec/specs/core_plugin_middleware_maxbodysize/` (after archive)
- Usage: one sentence on `knowledge/devdocs/core_plugin_middleware.md` (MaxBytesReader only when limit > 0)
- No runtime API, deploy key, or cap-value change
