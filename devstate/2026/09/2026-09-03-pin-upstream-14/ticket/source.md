# Pin plugin half of acouvreur/traefik-modsecurity-plugin#14

Purpose: add test coverage that verifies the plugin half of acouvreur/traefik-modsecurity-plugin#14 does **not** happen here: a 228565-byte WebDAV PUT is not denyVerbsWithBody, fits the 8 MiB cap, is forwarded to the sidecar, and sidecar 400/413 is copied as a block. Do not add a plugin knob that shadows SecRequestBodyNoFilesLimit. Do not change demo compose/README in this ticket (docs P2 is out of scope).

Starter file already untracked:
`pkg/modsecurity/upstream_issue_14_test.go`
Land that coverage (adapt if origin/main APIs differ). Tests only.

Short-reference: [acouvreur/traefik-modsecurity-plugin#14](https://github.com/acouvreur/traefik-modsecurity-plugin/issues/14)
