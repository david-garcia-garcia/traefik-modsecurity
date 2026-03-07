## Context

The plugin builds the URL for forwarding requests to ModSecurity by concatenating `modSecurityUrl` with `req.RequestURI`:

```go
url := a.modSecurityUrl + req.RequestURI
```

`req.RequestURI` is the raw, unmodified Request-URI from the HTTP request line. HTTP allows two forms:
- **origin-form** (normal): `/path?query`
- **absolute-form** (HTTP/1.0 clients, proxy-style clients): `http://example.com/path?query`

When absolute-form arrives, the concatenation produces `http://waf:8080http://example.com/path` — an invalid URL that fails DNS resolution.

Go's `net/http` server always parses the request URL into `req.URL`, and `req.URL.RequestURI()` always returns origin-form regardless of what was on the wire.

## Goals / Non-Goals

**Goals:**
- Correctly forward requests to ModSecurity regardless of whether the incoming RequestURI is origin-form or absolute-form
- No regression for the common HTTP/1.1 case

**Non-Goals:**
- Handling other exotic HTTP request forms (authority-form, asterisk-form — these are not relevant to plugin traffic)
- Any change to how query parameters, fragments, or encoding are handled

## Decisions

### Use `req.URL.RequestURI()` instead of `req.RequestURI`

`req.URL.RequestURI()` returns `path?query` (or just `path` when there is no query), always in origin-form. It is derived from the already-parsed `req.URL` which Go's HTTP server populates unconditionally.

**Alternatives considered:**
- **Parse and re-normalise `req.RequestURI` manually** — unnecessary complexity; Go already does this correctly in `req.URL`.
- **Detect absolute-form and strip the scheme+host** — fragile string manipulation; `req.URL.RequestURI()` is the canonical answer from the standard library.

## Risks / Trade-offs

- **[Risk]** Fragment identifier (`#anchor`) in URL → `req.URL.RequestURI()` excludes fragments (as per RFC 3986 for HTTP requests), same as `req.RequestURI`. No change in behaviour.
- **[Risk]** Encoded characters in path → `req.URL.RequestURI()` preserves percent-encoding from the original URL. No change in behaviour.

## Migration Plan

Single-line change, no config changes, no API changes, no data migration. Deploy as a patch release.
