# Local ticket

IssueKey: 2026-09-03-pin-upstream-09
issueHost: local
issueRef: none

## Title

Pin that acouvreur/traefik-modsecurity-plugin#9 (MaxBytesReader limit 0 → every POST 413) does not happen here

## Body

Purpose: add test coverage that verifies acouvreur/traefik-modsecurity-plugin#9 (MaxBytesReader limit 0 → every POST 413) does **not** happen here: omitted/`0` maxBodySizeBytes is prepared to 8 MiB and a login-sized POST is 200; a leftover handler field 0 skips MaxBytesReader instead of 413ing. Do not change product cap behavior. README drift is out of scope (#20).

Starter file already untracked:
`pkg/modsecurity/upstream_issue_09_test.go`
Land that coverage (adapt if origin/main APIs differ). Tests only.

Short-reference: [acouvreur/traefik-modsecurity-plugin#9](https://github.com/acouvreur/traefik-modsecurity-plugin/issues/9)
