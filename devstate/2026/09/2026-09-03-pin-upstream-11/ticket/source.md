# 2026-09-03-pin-upstream-11

Purpose: add test coverage that verifies acouvreur/traefik-modsecurity-plugin#11 (large non-file POST → client 500) does **not** happen here: plugin oversize is 413 blocked; sidecar 413 is copied as a block; sidecar 5xx is 502 error — never a forwarded client 500. Do not change status mapping. File vs non-file is not a plugin distinction.

Starter file already untracked:
`pkg/modsecurity/upstream_issue_11_test.go`
Land that coverage (adapt if origin/main APIs differ). Tests only.
