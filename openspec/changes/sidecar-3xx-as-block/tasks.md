## 1. Write failing test

- [ ] 1.1 Add a `TestModsecurity_ServeHTTP` case where the mock WAF returns 302 with no Location and assert the client gets 302, not the backend body
- [ ] 1.2 Add a case where the mock WAF returns 302 with Location to a 200 notice page and assert the client gets 302 plus that Location and `next` is not called
- [ ] 1.3 Run `go test -count=1 -run TestModsecurity_ServeHTTP` and confirm the new cases fail on current `>= 400` / default-follow behavior

## 2. Implement

- [ ] 2.1 Set the WAF `http.Client` `CheckRedirect` to return `http.ErrUseLastResponse` in `pkg/modsecurity/plugin.go`
- [ ] 2.2 Change the block gate in `pkg/modsecurity/serve.go` from `>= 400` to `>= 300`
- [ ] 2.3 Re-run `go test -count=1 -run TestModsecurity_ServeHTTP` and confirm the new cases pass; existing 200/403/406 cases still pass

## 3. Docs

- [ ] 3.1 Update `knowledge/devdocs/core_plugin_middleware.md` so the block line says sidecar status `>= 300` and that the WAF client does not follow redirects
