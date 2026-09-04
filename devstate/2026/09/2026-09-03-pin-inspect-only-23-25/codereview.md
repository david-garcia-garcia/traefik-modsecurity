# Code review
pin: origin/main...HEAD excluding devstate/ and .cursor/
head: b0f7d3a74891141d6c8dee9541b2274d42dda0ff

## Standards
none

## Spec
none

## Security
none

## Performance
1. [judgement] Unbounded payload — `scripts/integration-tests.Tests.ps1:172` — 16 MiB `New-RequestBodyOfSizeBytes` on the drain It. Volume is a fixed fixture, not a live growing input. Timeout is 60s. Same helper and size as `integration-tests.BodySize.Tests.ps1`. No apply.

## Applied
none.

## Recorded and skipped
- Performance 1: judgement; fixed 16 MiB test fixture with timeout; existing helper.

Standards: 0 findings, worst: none
Spec: 0 findings, worst: none
Security: 0 findings, worst: none
Performance: 1 finding, worst: judgement 16 MiB test body at `scripts/integration-tests.Tests.ps1:172`
