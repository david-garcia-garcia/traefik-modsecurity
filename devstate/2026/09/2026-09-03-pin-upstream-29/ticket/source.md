# Local caller spec

Purpose: add test coverage that verifies acouvreur/traefik-modsecurity-plugin#29 (allow-path lost backend CORS headers) does **not** happen in native Go: WAF 200 + next CORS/X-Backend survive on httptest.Server and Recorder; sidecar headers do not leak. Do not change ServeHTTP. Yaegi wrapping is out of scope.

Starter file already untracked:
`pkg/modsecurity/upstream_issue_29_test.go`
Land that coverage (adapt if origin/main APIs differ). Tests only.

Short-reference: [acouvreur/traefik-modsecurity-plugin#29](https://github.com/acouvreur/traefik-modsecurity-plugin/issues/29)
