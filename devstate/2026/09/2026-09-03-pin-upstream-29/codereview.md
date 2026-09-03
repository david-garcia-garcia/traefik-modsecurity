# Code review

Pin: `origin/main` (`2f39486`) ... `HEAD`. Command: `git diff origin/main...HEAD -- . ':!devstate' ':!.cursor'`.

Commits: `0b8f392` start, `6bee2e3` prepare, `b1e71b6` explore, `b8fb3c0` propose, `8972854` test.

## Standards

1. [hard] Leave a trail — `pkg/modsecurity/upstream_issue_29_test.go` — `issue29WAF`, `issue29NewRoute`, `issue29AssertClientHeaders` had no job comments
   → Added a one-line comment on each helper

## Spec

none

Requirement walk:
- Allow path keeps next response headers — locked by `TestPlugin_UpstreamIssue29_AllowPathKeepsBackendHeaders`; `serve.go` unchanged (already true on DestBranch)

## Security

none

## Performance

none

## Applied

- Standards 1: job comments on the three test helpers

## Recorded and skipped

none.

Standards: 1 finding, worst: Leave a trail at `pkg/modsecurity/upstream_issue_29_test.go` (applied)
Spec: 0 findings, worst: none
Security: 0 findings, worst: none
Performance: 0 findings, worst: none
