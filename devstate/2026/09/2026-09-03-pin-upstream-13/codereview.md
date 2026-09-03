# Code review
Pin: origin/main...HEAD excluding `devstate/` and `.cursor/`
Fixed point: origin/main (2f39486)
Reviewed head: 153a4f8
Change: pin-upstream-authelia-405

Four-axis review on the main thread (Task spawn skipped: this run is already a conductor subagent).

## Standards
none

## Spec
none

Requirement walk:
- Allow path drains (SHALL NOT 405 on allow) — `pkg/modsecurity/upstream_issue_13_test.go` allow case
- Block path copies 405 — same file sidecar 405 case
- Sidecar Host is inbound Host on firstfactor POST — same file `sawHost`
- Sidecar does not invent XFF hop — same file `sawForwarded` / `sawRealIP`

## Security
none

Fixture `password=secret` is a labeled dummy login POST, not a live credential. No new egress, headers, or fail-open.

## Performance
none

`io.ReadAll` is on a fixed fixture body in a unit test, not a growing production path.

Standards: 0 findings, worst: none
Spec: 0 findings, worst: none
Security: 0 findings, worst: none
Performance: 0 findings, worst: none

## Applied
none.

## Recorded and skipped
none.
