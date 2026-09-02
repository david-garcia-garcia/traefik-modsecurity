## Context

See proposal.md — Why. Plugin runtime on `origin/main` already implements negative `Prepare`, body pooling with `buf.Bytes()` aliased until after `next`, and sidecar Host/XFF copy. This change is tests plus the `go.yml` Test command.

`Prepare` maps window `0` and threshold `0` to CreateConfig defaults, so a ServeHTTP zero-window case is not a public-config path.

## Goals / Non-Goals

**Goals:**

- Isolate `TestModsecurity_ServeHTTP` rows so a later case cannot observe an earlier case's body or status header.
- Cover every `rejectNegative` field through `Prepare`.
- Exercise concurrent pooled vs ad-hoc body reads on one Plugin core under `-race`.
- Make that race check run on PRs via `go.yml`.

**Non-Goals:**

- Changing `ServeHTTP`, `Prepare`, or the body pool.
- Passing `-race` on `build.yml`.
- A ServeHTTP test for `health.New` window 0.
- Extra inbound-header assertions beyond Host / XFF / X-Real-Ip.

## Decisions

- Clone at the table-row site (`req.Clone(req.Context())`) rather than rebuilding the table around a factory. The existing rows already clone except two.
- Put remaining `rejectNegative` cases in `pkg/modsecurity/config_test.go` as a table next to the existing timeout and max-body tests, calling `Prepare` directly.
- Put the concurrent mixed-body test in `pkg/modsecurity/body_pool_test.go` because that file already owns pool vs ad-hoc allocation. Drive one Plugin core (`newTestBodyPoolRoute` or equivalent), fan out POSTs with a small pooled body and a large known-length body, assert sidecar and next saw each payload.
- Add `-race` only to `.github/workflows/go.yml` `go test`. Alternative considered: both workflows — rejected because they already overlap on every PR and a second race run doubles CI time.

## Risks / Trade-offs

- [Race tests are slower] → Mitigation: keep the concurrent test bounded (tens of goroutines, small payloads); `-race` only on `go.yml`.
- [`build.yml` can still miss a race] → Mitigation: accepted; documented in the go-test spec. `go.yml` is the named Test job.

## Migration Plan

None. Tests and one CI command. No operator config change.
