## Context

See proposal.md for motivation. `Prepare` already owns empty-URL and `logLevel` rejection plus `== 0` defaults. `New` copies prepared fields onto the client and core. `ServeHTTP` concatenates `modSecurityUrl` with `RequestURI()` and installs `MaxBytesReader` only when `maxBodySizeBytes > 0`. Go `url.Parse` + `IsAbs` define absolute; `Client.deadline` treats `Timeout <= 0` as no deadline (`knowledge/research/ext_http_url_parse/`, `ext_http_client_timeout/`).

## Goals / Non-Goals

**Goals:**

- Fail in `Prepare` for numeric `< 0` and for a WAF URL that is not an absolute `http`/`https` host with no path.
- Trim a lone trailing slash so concatenation cannot produce `//path`.
- Keep `== 0` defaulting unchanged.

**Non-Goals:**

- Changing CreateConfig default numbers or README “0 means unlimited” copy.
- Changing `ServeHTTP` join to `url.JoinPath` or `ResolveReference`.
- Changing `health.New` internal `< 0` never-trip; public config cannot reach it.

## Decisions

1. **Validate in `Prepare` only.** It already fails construction. Do not add a second check in `New` or `ServeHTTP`. Alternative: validate in `New` — rejected; `New` already calls `Prepare`.

2. **`url.Parse` then inspect fields.** Require `err == nil`, `IsAbs()`, scheme `http` or `https` (case-insensitive), non-empty `Host`, `Path` empty or `/`, empty `RawQuery`, nil `User`, empty `Fragment`. Then `strings.TrimRight` the raw string’s trailing `/` (or `parsed.String()` after clearing Path) and store that. Alternative: regex — rejected; Parse owns the grammar.

3. **Reject query, userinfo, and fragment.** Ticket said host and no path. Extra parts would still concatenate incorrectly or leak credentials into the reclaim key. Alternative: allow and strip — rejected; fail loudly.

4. **Reject every numeric field `< 0` with one helper.** Fields: the ten listed in the spec. Alternative: only body/timeout/pool — rejected; ticket said each numeric field; a negative backoff or conn limit is the same class of typo.

5. **Do not change zero semantics.** `UnhealthyWafBackOffPeriodSecs`, `UnhealthyWafFailureWindowSecs`, and `ResponseHeaderTimeoutMillis` stay 0-means-disabled. Others stay 0-means-CreateConfig-default.

## Risks / Trade-offs

- [Operators with a path prefix on `modSecurityUrl`] → Mitigation: none in tree or compose; reject per ticket. Document in usage packet.
- [IPv6 host URLs] → Mitigation: `url.Parse` Host form `[::1]:80` is a host; accept.
- [httptest `Server.URL` may include a trailing slash in some versions] → Mitigation: trim `/`; existing tests stay green.

## Migration Plan

- Deploy as a plugin version bump. Misconfigured middlewares fail Traefik route load instead of serving.
- Rollback: previous plugin version. No persisted schema.
