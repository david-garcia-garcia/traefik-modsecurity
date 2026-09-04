# Code review
IssueKey: 2026-09-04-fail-open-close
Fixed point: origin/main (aa6714d)
Diff: `git diff origin/main...HEAD -- . ':!devstate' ':!.cursor'`

## Standards
none

## Spec
1. [extra] `pkg/modsecurity/body_test.go` — `TestPlugin_InboundBodyReadFailureLeavesStatusHeaderUnset` locks inbound body-read 502 leaving the status header unset; no `waf-fail-closed` requirement names that path (commit `a428841`; `replyInboundBodyReadFailure` behavior is unchanged vs `origin/main`).
2. [extra] `knowledge/devdocs/core_plugin_middleware.md` — usage bullet that inbound body-read failure (non-413) must leave the status header unset; not asked by any fail-closed / waf-status / health-tracker / log-level / sidecar-response requirement in this change (companion to item 1).

## Security
none

## Performance
none

Standards: 0 findings, worst: none
Spec: 2 findings, worst: extra inbound body-read status-header test/docs not in this change’s SHALLs
Security: 0 findings, worst: none
Performance: 0 findings, worst: none

## Applied
none.

## Recorded and skipped
- Spec 1: extra test from a human correction that `error` is WAF-only; not missing/wrong; unattended does not revert it
- Spec 2: extra usage bullet for the same correction; not missing/wrong
