# Codereview
pin: origin/main...HEAD (exclude devstate/ .cursor/)

## Standards
1. [hard] Name for the scope — `pkg/modsecurity/plugin.go` — `pathBypass` hid the compiled allowlist
   → Applied: local renamed to `compiledBypass`
2. [hard] Leave a trail — `pkg/modsecurity/bypass.go` — `compileBypassByMethod` lacked block intros
   → Applied: comments on bucket / fallback compile / per-method fill / method-only leftovers
3. [hard] Leave a trail — `pkg/modsecurity/bypass.go` — `compiledMethodRegexp` comment restated the name
   → Applied: comment now states match-all vs join job
4. [hard] Leave a trail — `pkg/modsecurity/bypass_test.go` — Test functions had no job comments
   → Applied: one-line comments on each Test
5. [judgement] Mysterious Name — `alwaysMethod` / `alwaysAny` — recorded, not renamed

## Spec
none

## Security
none

## Performance
none

## Applied
- standards 1: rename pathBypass to compiledBypass
- standards 2: block comments in compileBypassByMethod
- standards 3: compiledMethodRegexp job comment
- standards 4: Test function comments

## Recorded and skipped
- standards 5: judgement Mysterious Name on alwaysMethod/alwaysAny; not a commandment hard find after comments
