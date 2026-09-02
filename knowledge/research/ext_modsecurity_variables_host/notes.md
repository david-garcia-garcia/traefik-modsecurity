# Host

ModSecurity and OWASP CRS read the request Host from the HTTP Host header: `REQUEST_HEADERS:Host`. They do not take Host from `X-Forwarded-Host` or from the sidecar’s own server name.

If the WAF engine never sees the original Host header, Host-sensitive CRS rules evaluate the wrong value.

## Official: REQUEST_HEADERS:Host is the Host header

ModSecurity Reference Manual (v3.x): `REQUEST_HEADERS` is the request-header collection, or `REQUEST_HEADERS:Header-Name` for one field. The documented example is:

`SecRule REQUEST_HEADERS:Host "^[\d\.]+$" "deny,id:47,log,status:400,msg:'Host header is a numeric IP address'"`

Note: multiple headers with the same name follow the web server (Apache concatenates with comma).

Owner: [Reference Manual (v3.x) — REQUEST_HEADERS](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v3.x)#request_headers).

Extract: `.sources/modsecurity-reference-manual-v3-request-headers.md`

v2.x Variables page: the same Host example.

Owner: [Reference Manual (v2.x) Variables — REQUEST_HEADERS](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v2.x)-Variables#request_headers).

## Source: CRS protocol rules use REQUEST_HEADERS:Host

`coreruleset/coreruleset@96d9f99043b89f07fb5a4fdad1d7effbbbbcec1a` (shallow master, 2026-09-01), `ver:'OWASP_CRS/4.30.0-dev'`.

`rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf`:

- 920280: `&REQUEST_HEADERS:Host "@eq 0"` — missing Host header.
- 920290: `REQUEST_HEADERS:Host "@rx ^$"` — empty Host header.
- 920350: `REQUEST_HEADERS:Host` matches a numeric IPv4 / IPv6 (optional port) — “Host header is a numeric IP address.”

No `X-Forwarded-Host` in those rules.

Owner: `coreruleset/coreruleset@96d9f99:rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf`.

Extract: `.sources/request-920-protocol-enforcement.md`

Client IP is `REMOTE_ADDR`, not this header. See `knowledge/research/ext_modsecurity_variables_remote-addr/`.
