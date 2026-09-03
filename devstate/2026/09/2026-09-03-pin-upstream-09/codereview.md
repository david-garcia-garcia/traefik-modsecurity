# Code review
pin: origin/main...HEAD excluding destate/ and .cursor/
change: pin-upstream-issue-09

## Standards
1. [hard] Name for the scope — `pkg/modsecurity/upstream_issue_09_test.go:23` — `h` was a placeholder for the #9 harness
   → Rename to `harness` (applied)
2. [hard] Leave a trail — `pkg/modsecurity/upstream_issue_09_test.go:15` — `issue09Harness` and `postIssue09Login` had no job comment
   → Add type and helper comments (applied)
3. [judgement] Duplicated Code — `pkg/modsecurity/upstream_issue_09_test.go:63` — three POST cases repeat 413/200/next asserts
   → Keep copies; each case names a different prepare path

## Spec
none

Requirement walk:
- Omitted or zero maxBodySizeBytes prepares to the CreateConfig default — `TestUpstreamIssue09_OmittedMaxBodySizeBytesSmallPOSTIs200`, `TestUpstreamIssue09_ExplicitZeroMaxBodySizeBytesSmallPOSTIs200`
- Login-sized POST is allowed under the prepared default cap — same two tests assert 200 and next
- Zero leftover handler cap does not install MaxBytesReader — `TestUpstreamIssue09_ForcedZeroHandlerLimitDoesNot413`

## Security
none

No new sources or sinks. Login body is a dummy form string. Stdlib MaxBytesReader case does not install a network listener.

## Performance
none

Fixed fixture body (`issue09LoginBody`). No growing collection, no unbounded ReadAll on a live input beyond the login-sized POST.

Standards: 3 findings, worst: Name for the scope at `pkg/modsecurity/upstream_issue_09_test.go:23`
Spec: 0 findings, worst: none
Security: 0 findings, worst: none
Performance: 0 findings, worst: none

## Applied
- Standards 1: renamed `h` to `harness`
- Standards 2: comments on `issue09Harness` and `postIssue09Login`

## Recorded and skipped
- Standards 3: judgement Duplicated Code — three cases stay separate so a single helper would hide which prepare path failed
