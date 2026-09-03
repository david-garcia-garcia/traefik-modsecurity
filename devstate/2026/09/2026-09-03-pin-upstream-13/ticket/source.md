# Local dump — 2026-09-03-pin-upstream-13

Purpose: add test coverage that verifies [acouvreur/traefik-modsecurity-plugin#13](https://github.com/acouvreur/traefik-modsecurity-plugin/issues/13) (Authelia login POST 405) is not a status this plugin invents: POST /api/firstfactor with portal Host/XFF is either next-on-allow (not 405) or a copied sidecar 405. Do not add Authelia/ForwardAuth compose or a 405 knob.

Starter file already untracked:
`pkg/modsecurity/upstream_issue_13_test.go`
Land that coverage (adapt if origin/main APIs differ). Tests only.
