# Code review
Fixed point: origin/main
Diff: `git diff origin/main...HEAD -- . ':!devstate' ':!.cursor'`

## Standards
1. [hard] One job, one owner — `scripts/integration-tests.Tests.ps1` — both new threshold Its pasted the same stop-WAF / three-failure / pass-through setup already used by the sibling trip It
   → Extract into `TestHelpers.ps1` `Invoke-ThresholdTestFailOpenTrip` and call it from all three threshold trip Its

## Spec
none

## Security
none

## Performance
none

## Applied
- Standards 1: extracted `Invoke-ThresholdTestFailOpenTrip`; three `/threshold-test` trip Its call it; listed the helper in `knowledge/devdocs/build_testing_integration.md`

## Recorded and skipped
none.

Standards: 1 finding, worst: One job, one owner (threshold trip duplicated)
Spec: 0 findings, worst: none
Security: 0 findings, worst: none
Performance: 0 findings, worst: none
