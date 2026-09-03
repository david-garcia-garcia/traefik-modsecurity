# REMOTE_ADDR

ModSecurity’s client IP variable is `REMOTE_ADDR`: the IP of the remote client as the **web server** reported it. The engine does not parse `X-Forwarded-For` itself. OWASP CRS (3.0.1 onward) does not fold that header into `REMOTE_ADDR` or `TX.real_ip`.

`X-Forwarded-For` remains an ordinary request header (`REQUEST_HEADERS:X-Forwarded-For`). It becomes `REMOTE_ADDR` only if the server (Apache `mod_remoteip`, nginx `real_ip`, …) rewrote the client IP **before** ModSecurity read it.

The official Apache CRS image loads `mod_remoteip` with `RemoteIPHeader X-Forwarded-For`, but it trusts only `REMOTEIP_INT_PROXY` (default `10.1.0.0/16`). A TCP peer outside that range leaves `REMOTE_ADDR` as the peer (Traefik).

## Official: REMOTE_ADDR is the remote client IP

ModSecurity Reference Manual (v3.x, current as of v3.0.6): “This variable holds the IP address of the remote client.” Example: `SecRule REMOTE_ADDR "@ipMatch 192.168.1.101"`. Persistent IP collections use `initcol:ip=%{REMOTE_ADDR}`.

The same page documents `REQUEST_HEADERS` as the request-header collection and uses `REQUEST_HEADERS_NAMES "^x-forwarded-for"` as an example of detecting a proxy **header name**, not as the client IP.

Owner: [Reference Manual (v3.x) — REMOTE_ADDR](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v3.x)#remote_addr).

Extract: `.sources/modsecurity-reference-manual-v3-variables.md`

v2.x Variables page: the same REMOTE_ADDR sentence. `USERAGENT_IP` is Apache 2.4-only: “the client ip address set by mod_remoteip in proxied connections.”

Owner: [Reference Manual (v2.x) Variables — REMOTE_ADDR](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v2.x)-Variables#remote_addr), [USERAGENT_IP](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v2.x)-Variables#useragent_ip).

Extract: `.sources/modsecurity-reference-manual-v2-variables.md`

## Source: Apache 2.4 REMOTE_ADDR follows useragent_ip when mod_remoteip is linked

Pinned: `owasp-modsecurity/ModSecurity` branch `v2/master` `@0875b1928003fa77ad5d2dcd61c531149ded7781`. Temp clone; deleted after extract.

Transaction init (`apache2/mod_security2.c`): Apache 2.4 sets `msr->remote_addr = r->connection->client_ip` (TCP peer) and `msr->useragent_ip = r->useragent_ip`.

`REMOTE_ADDR` generate (`apache2/re_variables.c`): on Apache 2.4 (`AP_SERVER_MINORVERSION_NUMBER > 3`), if `ap_find_linked_module("mod_remoteip.c")` is non-NULL, copy `msr->r->useragent_ip` onto `msr->remote_addr` and return that. Otherwise return the stored TCP-peer `remote_addr`. The generator does not read `X-Forwarded-For`.

v3 libModSecurity `Transaction::processConnection` sets `REMOTE_ADDR` from the `client` string the **connector** passed in. No header parse.

Owner: `owasp-modsecurity/ModSecurity@0875b1928003fa77ad5d2dcd61c531149ded7781:apache2/re_variables.c` (`var_remote_addr_generate`), `apache2/mod_security2.c` (transaction init). v3: `owasp-modsecurity/ModSecurity@7ea9fefbe0ba409d8733b4d682c8c4c059cd028d:src/transaction.cc` (`processConnection`).

Extracts: `.sources/modsecurity-v2-remote-addr.md`, `.sources/modsecurity-v3-processconnection.md`

## Official: CRS stopped using X-Forwarded-For for TX.real_ip

CRS 3.0.1 (2017-05-09) CHANGES: “SECURITY: Removed insecure handling of X-Forwarded-For header.”

The CRS wiki draft for that release: the header “is no longer being taken into consideration to define the TX.real_ip variable.” Operators behind a proxy should “look into mod_remoteip or similar means to fill the variable REMOTE_ADDR correctly.”

Owner: [CRS CHANGES 3.0.1](https://github.com/coreruleset/coreruleset/blob/v4.3.0/CHANGES.md), [Draft 3.0.1 release message](https://github.com/coreruleset/coreruleset/wiki/Draft-3.0.1-release-message).

Extract: `.sources/crs-3.0.1-x-forwarded-for.md`

## Source: CRS IP collection uses remote_addr

`coreruleset/coreruleset@386f8db6e5f21ed8f0dc9fe8d15d4f59dd213d7a` (tag `v4.3.0`, this product’s `owasp/modsecurity-crs:4.3.0-…` line). Same shape on later master (`@96d9f99043b89f07fb5a4fdad1d7effbbbbcec1a`, `ver:'OWASP_CRS/4.30.0-dev'`).

`rules/REQUEST-901-INITIALIZATION.conf` rule 901320: when default collections are enabled, `initcol:ip=%{remote_addr}_%{MATCHED_VAR}` (UA hash). No `X-Forwarded-For` or `tx.real_ip` assignment in that file.

`rules/REQUEST-905-COMMON-EXCEPTIONS.conf` matches `REMOTE_ADDR` against `127.0.0.1,::1`.

Owner: `coreruleset/coreruleset@386f8db:rules/REQUEST-901-INITIALIZATION.conf`, `rules/REQUEST-905-COMMON-EXCEPTIONS.conf`.

Extract: `.sources/request-901-initialization.md`

## Official + source: Apache CRS image may rewrite via mod_remoteip

Official image docs (`coreruleset/modsecurity-crs-docker` README): Apache env `REMOTEIP_HEADER` default `X-Forwarded-For`; `REMOTEIP_INT_PROXY` default `10.1.0.0/16` (“client intranet IP addresses trusted to present the RemoteIPHeader value”).

Pinned HEAD `coreruleset/modsecurity-crs-docker@5e3cda3ee7d0e77d70e550df7298c80269776cde`:

- `apache/Dockerfile-alpine` / `apache/Dockerfile`: `REMOTEIP_HEADER='X-Forwarded-For'`, `REMOTEIP_INT_PROXY='10.1.0.0/16'`, uncomment `LoadModule remoteip_module`.
- `apache/conf/extra/httpd-vhosts.conf`: `RemoteIPHeader ${REMOTEIP_HEADER}` and `RemoteIPInternalProxy ${REMOTEIP_INT_PROXY}`.

This product’s Apache compose now sets `REMOTEIP_HEADER=X-Real-IP` and RFC1918 `REMOTEIP_INT_PROXY`. The `4.3.0-apache-alpine-202406090906` pin still hardcodes `RemoteIPHeader X-Forwarded-For` in `httpd-vhosts.conf`, so compose also mounts `crs-apache/httpd-vhosts.conf`. Image defaults alone (`X-Forwarded-For` + `10.1.0.0/16`) would miss typical `172.16.0.0/12` Docker bridges and would look at empty XFF.

Owner: [CRS Docker README — Apache ENV](https://github.com/coreruleset/modsecurity-crs-docker/blob/5e3cda3ee7d0e77d70e550df7298c80269776cde/README.md), `coreruleset/modsecurity-crs-docker@5e3cda3:apache/conf/extra/httpd-vhosts.conf`.

Extract: `.sources/crs-docker-apache-remoteip.md`

## Official: Apache only rewrites when the peer is trusted

`mod_remoteip` “overrides the client IP address for the connection with the useragent IP address reported in” `RemoteIPHeader`. “It is critical to only enable this behavior from intermediate hosts (proxies, etc) which are trusted.”

`RemoteIPHeader` default is **none**. “Unless these other directives are used, mod_remoteip will trust all hosts presenting a RemoteIPHeader IP value.” The CRS image **does** set `RemoteIPInternalProxy`, so only that intranet list is trusted.

Multiple comma-delimited IPs are processed **right-to-left**; processing stops at the first untrusted hop.

Owner: [Apache Module mod_remoteip](https://httpd.apache.org/docs/2.4/mod/mod_remoteip.html).

Extract: `.sources/httpd-mod-remoteip.md`

Host-sensitive CRS rules read `REQUEST_HEADERS:Host`, not this variable. See `knowledge/research/ext_modsecurity_variables_host/`.
