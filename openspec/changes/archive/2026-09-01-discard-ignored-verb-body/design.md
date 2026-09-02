## Context

See proposal.md Why. `ServeHTTP` already has two ignore-verb branches: deny reads one byte and may 400; otherwise the body-read block is skipped and `req.Body` is left for `next`. README already documents consume-and-withhold.

RFC 9110: GET/HEAD/DELETE content has no generally defined semantics. Framing still exists. Research: `knowledge/research/ext_http_methods_request-content/`.

## Goals / Non-Goals

**Goals:**

- Make the ignore-verb pass path match the documented contract: body is not inspected by the WAF and not delivered to `next`.
- Leave enough of an empty body that Traefik does not advertise leftover `Content-Length`.

**Non-Goals:**

- Flipping `ignoreBodyForVerbsDeny` default.
- Changing the default verb list.
- Sending ignored-verb bodies to ModSecurity.
- Discarding bodies on the WebSocket skip.

## Decisions

- Drain with `io.Copy(io.Discard, req.Body)`, then set `req.Body = http.NoBody`, `req.ContentLength = 0`, and delete `Content-Length`. Alternative considered: only `NoBody` — Traefik can still advertise `ContentLength` 18 (reproduced). Alternative considered: default deny true — breaking for GET-with-body clients; operators already have the knob.
- Drain even when deny is false and the body is empty or `http.NoBody`. `io.Copy` on `NoBody` is a no-op.
- Keep deny=true as the existing one-byte probe and 400. Do not drain after a 400 (handler returns).
- Unit-test in the root plugin package next to `TestModsecurity_ServeHTTP` (same `New` + mock WAF pattern). Do not add a new Pester compose service unless the unit test cannot see `next`'s body.

## Risks / Trade-offs

- [Risk] Backends that relied on GET/DELETE bodies (Elasticsearch, GraphQL-over-GET) stop seeing that payload → Mitigation: documented as the existing README contract; operators can remove the verb from `ignoreBodyForVerbs` to inspect and forward.
- [Risk] Drain of a huge ignored-verb body can block a worker → Mitigation: same as today's POST read; `MaxBytesReader` is not applied on the ignore path today. Do not add a new limit in this change (bound the ask). Operators who want reject use deny.
- Drain and deny run before the unhealthy early-forward so fail-open does not deliver an ignored-verb body to next.

## Migration Plan

Default config keys stay the same. Deploy is a behavior fix toward the documented contract. Rollback: revert the `ServeHTTP` discard.
