## 1. Write failing test

- [x] 1.1 Add a unit test in `pkg/modsecurity/serve_test.go` that cancels the inbound request context while a mock WAF blocks and asserts `ServeHTTP` returns before the configured `timeoutMillis`
- [x] 1.2 Run that test and confirm it fails on current `http.NewRequest` construction

## 2. Bind sidecar request to inbound context

- [x] 2.1 Change `pkg/modsecurity/serve.go` to build the sidecar request with `http.NewRequestWithContext(req.Context(), req.Method, url, bodyReader)`
- [x] 2.2 Re-run the cancel test and confirm it passes
- [x] 2.3 Re-run the existing Go tests that cover `ServeHTTP` (`serve_test.go`, `modsecurity_test.go`) and confirm they still pass

## 3. Usage note

- [x] 3.1 Update `knowledge/devdocs/core_plugin_middleware.md` so the outbound WAF call is documented as bound to the inbound request context
