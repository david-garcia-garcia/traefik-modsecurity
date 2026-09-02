## Context

See proposal.md — Why. The block gate is `resp.StatusCode >= 400` in `pkg/modsecurity/serve.go`. The shared WAF client in `pkg/modsecurity/plugin.go` is a stock `http.Client` (default follow-up to 10 redirects). Explore measured both: a bare 302 calls `next`, and a 302 with Location is followed so the final 200 also calls `next`.

## Goals / Non-Goals

**Goals:**

- Surface the sidecar's own status to the block gate.
- Treat any non-success sidecar status as a block using the same `forwardResponse` path.

**Non-Goals:**

- A configurable allowed-status set
- New log lines
- Sidecar or CRS rule changes

## Decisions

- **Threshold 300, not a config list.** Same shape as today's `>= 400`. Ticket listed config as an alternative. Allow is `< 300`.
- **`CheckRedirect` returns `http.ErrUseLastResponse`.** That is the stdlib way to keep `Do` from following. Alternative: custom transport — rejected; the client already owns redirect policy.
- **No new public config.** Consumer-visible change is request-path behavior only.

## Risks / Trade-offs

- [Risk] A sidecar that returns 3xx on a true allow would start blocking. → Mitigation: supported compose sidecar and tests use 200 for allow; documented as assumed in explore.
- [Risk] Tests that use `http.Redirect` on the mock WAF would start asserting 302 instead of a followed 200. → Mitigation: add explicit 302 cases; keep 200 allow cases.
