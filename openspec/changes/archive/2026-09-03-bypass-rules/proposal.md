## Why

Operators have no way to skip the ModSecurity sidecar for selected admin or high-frequency method+path patterns. The only workaround is a separate Traefik router without this middleware. A named fork added `bypassRules` but matched with a per-request scan of every compiled rule, which does not scale.

## What Changes

- Add public `bypassRules` (`method` + `pathRegexp`, both optional) matching the DNAstack surface.
- Compile at prepare into one regexp per HTTP method (path regexes wrapped as `(?:…)` and joined with `|`). ServeHTTP does one map lookup and at most one `MatchString` on `req.URL.Path`. Do not keep a per-rule slice scan.
- Matching requests skip body buffering and the sidecar. When `modSecurityStatusRequestHeader` is set, write `bypassrule`.
- Invalid `pathRegexp` fails plugin construction.
- README documents the new key and the new status token.

## Capabilities

### New Capabilities

- `core_plugin_middleware_bypass-rules`: Operator `bypassRules` allowlist that skips sidecar inspection for matching method+path patterns using one compiled regexp per method.

### Modified Capabilities

- `core_plugin_middleware_status-header`: When a bypass rule matches and the header name is set, write `bypassrule` (not `ok`, not unset).

## Impact

- `pkg/modsecurity/config.go` — `BypassRule`, `Config.BypassRules`, Prepare compile/validate
- `pkg/modsecurity/bypass.go` — compile map + match helper (new file)
- `pkg/modsecurity/plugin.go` — store compiled map
- `pkg/modsecurity/serve.go` — early exit before websocket / body / sidecar
- `pkg/modsecurity/` tests for match, miss, header, invalid regexp, method-only, path-only
- `README.md` configuration
- `knowledge/devdocs/core_plugin_middleware.md` — Language + usage for bypass rules
- Specs: new `core_plugin_middleware_bypass-rules`; modified `core_plugin_middleware_status-header`
