---
url: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v3.x)
title: Reference Manual (v3.x) — REMOTE_ADDR and REQUEST_HEADERS
fetched: 2026-09-01
authority: official
---

Wiki banner: DRAFT, current as of v3.0.6.

REMOTE_ADDR: “This variable holds the IP address of the remote client.”

Example: `SecRule REMOTE_ADDR "@ipMatch 192.168.1.101" "id:35"`

REMOTE_HOST in v3 is a synonym for REMOTE_ADDR.

REQUEST_HEADERS: collection of request headers, or `REQUEST_HEADERS:Header-Name` for one header. Example uses `REQUEST_HEADERS:Host`.

REQUEST_HEADERS_NAMES example: `SecRule REQUEST_HEADERS_NAMES "^x-forwarded-for" "log,deny,id:48,status:403,t:lowercase,msg:'Proxy Server Used'"` — treats X-Forwarded-For as a header name, not as REMOTE_ADDR.

Collection examples elsewhere on the same page: `initcol:ip=%{REMOTE_ADDR}` / `initcol:IP=%{REMOTE_ADDR}`.

`@ipMatch` / `@ipMatchFromFile` / `@rbl` / `@geoLookup` examples all operate on `REMOTE_ADDR`.
