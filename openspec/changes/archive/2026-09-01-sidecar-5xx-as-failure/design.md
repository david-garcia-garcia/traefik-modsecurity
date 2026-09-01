## Context

See proposal.md for motivation. `pkg/modsecurity/serve.go` already has two outcomes after `httpClient.Do`: transport `err != nil` (optional `RecordFailure`, fail-open or 502) and `resp.StatusCode >= 400` (block). Explore reproduced a mock 503 taking the block path. Reuse the existing tracker; do not add a second backoff.

## Goals / Non-Goals

**Goals:**

- One status-class split: `< 400` pass, `4xx` block, `5xx` failure.
- 5xx shares the transport-error outcome (tracker + fail-open / 502).
- Every 5xx sets the status request header to `error` when configured.

**Non-Goals:**

- Configurable block-status allowlist.
- Changing transport-error header behavior (still `error` only on the trip request).
- 3xx handling, numeric block status, health-tracker default retune.

## Decisions

1. **Threshold is `>= 500`, not a deny-status list.** Alternative: only 502/503/504, or a config allowlist. Rejected: ticket asked for 5xx as failure; a list is a new public surface.

2. **Extract one failure helper for transport errors and 5xx.** Alternative: copy the `err != nil` block under a 5xx `if`. Rejected: two owners of fail-open would drift. The helper records failure, fail-opens or writes 502. The 5xx caller sets `error` on the header first; the transport caller keeps today's trip-only `error`.

3. **Do not forward the sidecar 5xx body.** Alternative: return the sidecar 5xx page when not failing open. Rejected: explore decided 502 empty, same as transport; forwarding a 503 page still looks like an application outage.

4. **Close the 5xx body via the existing deferred `Close`.** The helper must not `forwardResponse` on 5xx.

## Risks / Trade-offs

- [Risk] A configured ModSecurity `deny,status:500` becomes a health failure. → Mitigation: documented as assumed in explore.md; no allowlist in this change.
- [Risk] Operators who scrape sidecar 5xx pages lose that body. → Mitigation: they get `error` on the request header and 502 or fail-open, which is the intended signal.

## Migration Plan

No config migration. Deploy the plugin version. Rollback is the previous version (5xx looks like a block again).
