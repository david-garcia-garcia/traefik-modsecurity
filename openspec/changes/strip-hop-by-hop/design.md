## Context

See proposal.md for motivation. The only copy site is `forwardResponse` in `pkg/modsecurity/serve.go`. Today it overwrites `rw.Header()` from `resp.Header` with no filter. RFC 9110 §7.6.1 requires intermediaries to drop `Connection` and names it lists; Traefik's own hop list is documented in `knowledge/research/ext_traefik_proxy_upgrade-headers`. Existing helpers `headerValuesContainToken` already parse comma-separated tokens.

## Goals / Non-Goals

**Goals:**
- One owner for the strip: `forwardResponse` (or a helper it calls in the same package).
- Canonical-name compare (HTTP header names are case-insensitive).
- Keep overwrite semantics for headers that remain.

**Non-Goals:**
- A shared hop-by-hop package used by request forwarding.
- Stripping `Set-Cookie` or rewriting the error-page body.
- Changing the `>= 400` block threshold.

## Decisions

- **Filter at copy time, not on the sidecar `http.Response`.** The sidecar object is not reused after the block return. Alternative: mutate `resp.Header` first — same effect, extra mutation of a value we close immediately.
- **`Proxy-*` is a prefix match** on the header name (`strings.HasPrefix(strings.ToLower(k), "proxy-")`). Alternative: only `Proxy-Authenticate` / `Proxy-Authorization` / `Proxy-Connection` (Traefik hopHeaders). Ticket text is `Proxy-*`.
- **Also drop names listed in sidecar `Connection`.** RFC 9110 MUST. Reuse comma-token parsing already in this file. Alternative: fixed list only — would miss a custom hop listed in `Connection`.
- **`Server` is a named drop, not hop-by-hop.** Fingerprint only. Alternative: rewrite `Server` to a generic value — extra surface, ticket says strip.
- **Document on README How it works.** That is the public statement operators already read. Usage gotcha on `core_plugin_middleware.md` when that packet is updated.

## Risks / Trade-offs

- [Sidecar `Content-Length` vs streamed body] → Go's client already decoded the entity; strip `Transfer-Encoding` and let `http.ResponseWriter` set length. Do not also strip `Content-Length` unless it is named in `Connection`.
- [Operators who relied on seeing `Server`] → document the strip; no config to turn it back on.
- [Error-page body still leaks rule IDs] → accepted; ticket asks for documentation, not sanitization.

## Migration Plan

Ship in the plugin version that includes this commit. No config migration. Rollback is revert of the filter.

## Open Questions

None. Explore decisions stand.
