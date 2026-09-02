## Context

`ServeHTTP` currently skips the body-read block for `ignoreBodyForVerbs`, optionally 400s when `ignoreBodyForVerbsDeny` is true, otherwise drains for `next`. Human rejected silent drain: HTTP 200 with an empty application body and no WAF log.

## Goals / Non-Goals

**Goals:**

- One array knob `denyVerbsWithBody`. Default verbs unchanged.
- Body on a listed method → HTTP 400 before sidecar and before `next`.
- Otherwise inspect and forward the body like POST.
- Nil/omitted → default list. Explicit empty → deny nothing.

**Non-Goals:**

- Changing which verbs are in the default list.
- A remaining skip-WAF-body list.
- WebSocket GET skip.
- Changing the 400 log line or status text.

## Decisions

- Probe one byte with `MaxBytesReader` (same as today’s deny path). Return 400 when `n > 0 || err == nil`.
- Run that probe before the unhealthy early-forward.
- `Prepare`: `if cfg.DenyVerbsWithBody == nil { copy defaults }`. Do not treat `len == 0` as omitted.
- Store a method map on the Plugin (`createMethodSet`). Drop `ignoreBodyForVerbs` / `ignoreBodyForVerbsDeny`.
- Always read the inbound body for the sidecar after the deny probe.

## Risks / Trade-offs

- [Risk] GET-with-body clients (Elasticsearch) get 400 on default config — Mitigation: README says remove `GET` from the list.
- [Risk] CRS may inspect GET bodies that `main` never sent to the sidecar when the operator empties the list — Mitigation: that is the inspect-and-forward path they opted into.
- [Risk] Leftover `ignoreBodyForVerbs` in a deploy file is silently ignored — Mitigation: README migration note; do not fail Prepare on unknown keys (Traefik decode).

## Migration Plan

Document the two removed keys and the new array. Rollback: revert the PR.
