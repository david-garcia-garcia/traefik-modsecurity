## Context

See proposal.md for motivation. All writes already live in `Plugin.ServeHTTP` (`pkg/modsecurity/serve.go`). `strconv` is already imported. The header is a request header for Traefik access logs; empty name remains off. `healthTracker` is nil when `unhealthyWafBackOffPeriodSecs` is 0.

## Goals / Non-Goals

**Goals:**

- One value per outcome so access logs can distinguish sidecar block, local 413, sidecar down, already-unhealthy, and cannot-forward.
- Client-fault rejections stop using Error.

**Non-Goals:**

- New config keys.
- Changing the `>= 400` block rule, tracker trip math, or `unhealthy` / `cannotforward` tokens.
- Response headers.

## Decisions

- **Decimal status on sidecar block.** `strconv.Itoa(resp.StatusCode)` at the existing `>= 400` site. Alternative (`blocked` plus a second header) rejected: README already documents the status string.
- **`toolarge` for local 413.** Same lowercase-word family as `unhealthy` / `error` / `cannotforward`. Alternative (`413`) rejected: a local reject must not look like a sidecar 413.
- **`error` before tracker pass-through.** Set the header whenever `httpClient.Do` returns an error and the name is configured, then keep today’s tracker / 502 / fail-open control flow. Alternative (only on 502) rejected: the ticket requires the value on every communication failure, including fail-open after this request’s failure.
- **Warn for client-fault logs.** `logger.Warn` on ignore-verb body and both MaxBytesError sites. Alternative (Debug) rejected: default `logLevel` is `info`, so Debug would hide the rejections.

## Risks / Trade-offs

- [Risk] Operators matching access-log value `blocked` for WAF blocks will stop matching. → Mitigation: README lists the status-code contract; treat as a documented fix, not a silent extra token.
- [Risk] A sidecar that itself returns 413 looks like a WAF block (`413`), not `toolarge`. → Mitigation: that is correct — `toolarge` is only the local MaxBytesError path.

## Migration Plan

Ship in one plugin version. Rollback is revert. No config migration.

## Open Questions

None. Token and log-level choices are on `devstate/explore.md`.
