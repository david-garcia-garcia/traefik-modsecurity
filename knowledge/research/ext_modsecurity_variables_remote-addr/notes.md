# REMOTE_ADDR

ModSecurity’s client IP variable is `REMOTE_ADDR`: the IP of the remote client as the engine received it from the web server. It is not `X-Forwarded-For`. OWASP CRS initializes IP collections from `%{remote_addr}`.

`X-Forwarded-For` is an ordinary request header (`REQUEST_HEADERS:X-Forwarded-For` / `REQUEST_HEADERS_NAMES`). CRS does not fold it into `REMOTE_ADDR`.

## Official: REMOTE_ADDR is the remote client IP

ModSecurity Reference Manual (v3.x, current as of v3.0.6): “This variable holds the IP address of the remote client.” Example: `SecRule REMOTE_ADDR "@ipMatch 192.168.1.101"`. Persistent IP collections use `initcol:ip=%{REMOTE_ADDR}`.

The same page documents `REQUEST_HEADERS` as the request-header collection and uses `REQUEST_HEADERS_NAMES "^x-forwarded-for"` as an example of detecting a proxy **header name**, not as the client IP.

Owner: [Reference Manual (v3.x) — REMOTE_ADDR](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v3.x)#remote_addr).

Extract: `.sources/modsecurity-reference-manual-v3-variables.md`

v2.x Variables page: the same REMOTE_ADDR sentence.

Owner: [Reference Manual (v2.x) Variables — REMOTE_ADDR](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v2.x)-Variables#remote_addr).

## Source: CRS IP collection uses remote_addr

`coreruleset/coreruleset@96d9f99043b89f07fb5a4fdad1d7effbbbbcec1a` (shallow master, 2026-09-01), `ver:'OWASP_CRS/4.30.0-dev'`.

`rules/REQUEST-901-INITIALIZATION.conf` rule 901320: when default collections are enabled, `initcol:ip=%{remote_addr}_%{MATCHED_VAR}` (UA hash). No `X-Forwarded-For` or `tx.real_ip` assignment in that file.

`rules/REQUEST-905-COMMON-EXCEPTIONS.conf` matches `REMOTE_ADDR` against `127.0.0.1,::1`.

Owner: `coreruleset/coreruleset@96d9f99:rules/REQUEST-901-INITIALIZATION.conf`, `rules/REQUEST-905-COMMON-EXCEPTIONS.conf`.

Extract: `.sources/request-901-initialization.md`

Host-sensitive CRS rules read `REQUEST_HEADERS:Host`, not this variable. See `knowledge/research/ext_modsecurity_variables_host/`.
