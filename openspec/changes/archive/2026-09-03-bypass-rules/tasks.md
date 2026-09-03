## 1. Config and compile

- [x] 1.1 Add `BypassRule` and `Config.BypassRules` with json tags `method` / `pathRegexp` / `bypassRules` in `pkg/modsecurity/config.go`
- [x] 1.2 In `Prepare`, compile each non-empty `pathRegexp` and fail with `invalid bypass rule pathRegexp %q`
- [x] 1.3 Add `pkg/modsecurity/bypass.go`: `compileBypassByMethod` builds uppercase method map plus `bypassAnyMethod`; join with `(?:p)|(?:q)`; empty pathRegexp is always-match for that method
- [x] 1.4 Store the compiled map on `Plugin` in `New`

## 2. ServeHTTP

- [x] 2.1 At the start of `ServeHTTP`, one map get of `strings.ToUpper(req.Method)` (fallback `bypassAnyMethod`) then one `MatchString` on `req.URL.Path`
- [x] 2.2 On match: set `modSecurityStatusRequestHeader` to `bypassrule` when the name is set, call `next`, return (before websocket, denyVerbsWithBody, body read, sidecar)

## 3. Tests

- [x] 3.1 Add `pkg/modsecurity/bypass_test.go` covering method+path match/miss, method-only, path-only, no rules, `bypassrule` header, empty header name, invalid regexp fails `New`, bypassed GET-with-body is not 400
- [x] 3.2 Run `go test ./pkg/modsecurity/ -run Bypass` and `go test ./...`

## 4. Docs

- [x] 4.1 Document `bypassRules` and status token `bypassrule` in `README.md` configuration
- [x] 4.2 Add Language **Bypass rule** and a usage bullet on `knowledge/devdocs/core_plugin_middleware.md`
