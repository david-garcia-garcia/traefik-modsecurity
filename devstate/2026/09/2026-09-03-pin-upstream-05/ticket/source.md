# Local dump

Title: Pin coverage for acouvreur/traefik-modsecurity-plugin#5 (HTTP/2 abort / Yaegi isWebsocket panic)

Purpose: add test coverage that verifies the HTTP/2 abort / Yaegi panic blamed on `isWebsocket` in acouvreur/traefik-modsecurity-plugin#5 does **not** happen on this plugin: `isWebsocket` does not panic; a reporter-shaped empty GET does not panic; inbound cancel does not nil-deref. Do not add `recover` in ServeHTTP. Do not change product behavior.

Starter file already untracked in the worktree:
`pkg/modsecurity/upstream_issue_05_test.go`
Land that coverage (adapt if origin/main APIs differ). Tests only unless a compile fix in the test helpers is required.
