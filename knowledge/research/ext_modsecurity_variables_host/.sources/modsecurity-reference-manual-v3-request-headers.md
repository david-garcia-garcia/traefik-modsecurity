---
url: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v3.x)
title: Reference Manual (v3.x) — REQUEST_HEADERS
fetched: 2026-09-01
authority: official
---

Wiki banner: DRAFT, current as of v3.0.6.

REQUEST_HEADERS: “This variable can be used as either a collection of all of the request headers or can be used to inspect selected headers (by using the REQUEST_HEADERS:Header-Name syntax).”

Example:

`SecRule REQUEST_HEADERS:Host "^[\d\.]+$" "deny,id:47,log,status:400,msg:'Host header is a numeric IP address'"`

Note: multiple headers with identical names follow the web server; for Apache they are concatenated with a comma.

v2.x Variables page (`https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v2.x)-Variables`) repeats the same REMOTE_ADDR sentence and the same REQUEST_HEADERS:Host example.
