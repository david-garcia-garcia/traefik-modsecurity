---
url: https://pkg.go.dev/net/url@go1.21.13
title: net/url package (go1.21.13)
fetched: 2026-09-03
authority: official
---

`type URL` — Path is “path (relative paths may omit leading slash).” RawPath is “encoded path hint (see EscapedPath method).”

“Note that the Path field is stored in decoded form: /%47%6f%2f becomes /Go/. A consequence is that it is impossible to tell which slashes in the Path were slashes in the raw URL and which were %2f. This distinction is rarely important, but when it is, the code should use the EscapedPath method, which preserves the original encoding of Path.”

“The RawPath field is an optional field which is only set when the default encoding of Path is different from the escaped path. See the EscapedPath method for more details.”

“URL's String method uses the EscapedPath method to obtain the path.”

`func (u *URL) EscapedPath() string` — “returns the escaped form of u.Path. In general there are multiple possible escaped forms of any path. EscapedPath returns u.RawPath when it is a valid escaping of u.Path. Otherwise EscapedPath ignores u.RawPath and computes an escaped form on its own. The String and RequestURI methods use EscapedPath to construct their results. In general, code should call EscapedPath instead of reading u.RawPath directly.”

`func (u *URL) JoinPath(elem ...string) *URL` — “returns a new URL with the provided path elements joined to any existing path and the resulting path cleaned of any ./ or ../ elements. Any sequences of multiple / characters will be reduced to a single /.”

`func JoinPath(base string, elem ...string) (result string, err error)` — same cleaning of `./` or `../` elements.

`func (u *URL) ResolveReference(ref *URL) *URL` — “resolves a URI reference to an absolute URI from an absolute base URI u, per RFC 3986 Section 5.2.”

`func Parse(rawURL string) (*URL, error)` — “parses a raw url into a URL structure.” Relative (path, no host) or absolute (scheme). No documented `.` / `..` collapse.

Canonical unversioned page: https://pkg.go.dev/net/url (same Path / RawPath / EscapedPath wording). Product `go.mod` is `go 1.21`.
