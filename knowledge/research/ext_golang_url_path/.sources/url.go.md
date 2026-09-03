---
url: https://github.com/golang/go/blob/go1.21.13/src/net/url/url.go
title: src/net/url/url.go
fetched: 2026-09-03
authority: source
ref: golang/go@go1.21.13:src/net/url/url.go
---

`URL` comment matches official docs: Path stored decoded (`/%47%6f%2f` → `/Go/`); slashes from `/` vs `%2f` indistinguishable on Path; use EscapedPath; RawPath only when default encoding of Path differs.

`Parse` cuts `#frag` then `parse`. `ParseRequestURI` calls `parse(rawURL, true)`. After authority, `parse` calls `url.setPath(rest)`.

`setPath(p)` unescapes `p` with `encodePath` into `u.Path`. If `escape(path, encodePath) == p`, `RawPath=""`. Else `RawPath=p`. Documented examples: `setPath("/foo/bar")` → Path `/foo/bar`, RawPath empty; `setPath("/foo%2fbar")` → Path `/foo/bar`, RawPath `/foo%2fbar`. No `path.Clean`, no `resolvePath`.

`EscapedPath` returns `RawPath` when `validEncoded(RawPath, encodePath)` and unescaping it equals `Path`. Else escapes `Path` (`*` left as `*`).

`resolvePath` applies `.` (drop) and `..` (pop) per RFC 3986. Callers: `ResolveReference` only (`setPath(resolvePath(...))`). Not used by `Parse` / `setPath`.

`JoinPath` joins via `path.Join` then `setPath`. Comment: resulting path cleaned of `./` or `../`; multiple `/` reduced to one.

Product `go.mod` is `go 1.21`; this extract is the go1.21.13 tag of the same API.
