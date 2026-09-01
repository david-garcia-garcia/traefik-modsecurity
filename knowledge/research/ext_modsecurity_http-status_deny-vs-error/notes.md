# Deny vs error HTTP status

ModSecurity security blocks typically return **403**. A configured `deny,status:N` can be **any integer**, including **5xx**. Apache/nginx sidecar failures when `BACKEND` is down or the proxy itself is broken typically return **502 / 503 / 504**, and sometimes **500**. **500 is therefore not a reliable “sidecar down” signal.**

## Deny, drop, redirect

`deny` stops rule processing and intercepts the transaction. The HTTP code comes from the `status` data action used with `deny` or `redirect`. Official examples use `status:403`. The v2 and v3 manuals do not restrict `status` to 4xx.

Owner: [Reference Manual (v2.x) Actions](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v2.x)-Actions) (`deny`, `status`, `redirect`, `drop`). Same `deny` / `status` wording on [Reference Manual (v3.x)](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v3.x)).

Extracts: `.sources/reference-manual-v2-actions.md`, `.sources/reference-manual-v3.md`

`redirect` uses 301, 302, 303, or 307 when `status` is one of those; otherwise **302**. `drop` on v2 closes the TCP connection (FIN); the v2 connector logs “Access denied with connection close” and uses `HTTP_FORBIDDEN` (403) when the close succeeds. On v3, official docs and source say `drop` currently runs as `deny`.

Owner: v2 Actions wiki (`redirect`, `drop`); v3 wiki (`drop` = deny); `owasp-modsecurity/ModSecurity@0875b19:apache2/mod_security2.c`; `owasp-modsecurity/ModSecurity@7ea9fef:src/actions/disruptive/drop.cc`.

Extracts: `.sources/mod_security2.c.md`, `.sources/drop.cc.md`

If `status` is omitted, deny defaults to **403**:

- v2 action-set init: `if (intercept_status == NOT_SET) intercept_status = 403`.
- v3 `Deny::evaluate`: if intervention status is still 200, set 403.

Owner: `owasp-modsecurity/ModSecurity@0875b19:apache2/re.c`; `owasp-modsecurity/ModSecurity@7ea9fef:src/actions/disruptive/deny.cc`.

Extracts: `.sources/re.c.md`, `.sources/deny.cc.md`

Apache `ErrorDocument` for that status runs when present. Phase 1 `status` settings can override Apache `Directory`/`Location` status settings.

Owner: [v2 Actions — status](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v2.x)-Actions); [Apache custom error responses](https://httpd.apache.org/docs/2.4/custom-error.html).

Extracts: `.sources/httpd-custom-error.md`

## Can deny return 5xx?

**Yes.** Official v3 manual examples include `deny,status:500`:

```
SecRule HIGHEST_SEVERITY "@le 2" "phase:2,id:23,deny,status:500,..."
SecRule ARGS "@pm some key words" "id:12345,deny,status:500"
```

Owner: [Reference Manual (v3.x)](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v3.x)) (`HIGHEST_SEVERITY`, `MODSEC_BUILD`).

The `status` parser accepts any decimal integer. v3 scanner: `status:[0-9]+`, then `std::stoi`. v2: `atoi(action->param)` with a TODO that validation of a “valid HTTP status code” was never added.

Owner: `owasp-modsecurity/ModSecurity@7ea9fef:src/parser/seclang-scanner.ll`, `src/actions/data/status.cc`; `owasp-modsecurity/ModSecurity@0875b19:apache2/re_actions.c`.

Extracts: `.sources/status.cc.md`, `.sources/seclang-scanner.ll.md`, `.sources/re_actions.c.md`

v2 also emits **500 on a deny with `intercept_status == 0`**, labeled “Internal Error: Invalid status code requested”. That 500 is a ModSecurity deny, not a sidecar crash.

Owner: `owasp-modsecurity/ModSecurity@0875b19:apache2/mod_security2.c`.

## SecDefaultAction and OWASP CRS defaults

Engine default if no `SecDefaultAction` is set: `phase:2,log,auditlog,pass`. Example usage in the manual: `deny,status:403`.

Owner: [Reference Manual (v2.x) Configuration Directives — SecDefaultAction](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v2.x)-Configuration-Directives). Same default on the v3 manual.

Extract: `.sources/reference-manual-v2-directives.md`

CRS default mode is anomaly scoring. `crs-setup.conf.example` ships:

```
SecDefaultAction "phase:1,log,auditlog,pass"
... through phase:5 ...
```

Comments: offending requests are blocked with **error 403**. Self-contained mode (commented) uses `deny,status:403` and says other codes such as 404, 406, etc. are allowed.

Inbound/outbound blocking rules `949110` / `949111` / `959100` / `959101` apply `deny` without a `status`. CRS says that deny is **by default paired with `status:403`**. Change it after CRS with `SecRuleUpdateActionById` (examples: `deny,status:404`, `redirect`, `drop`).

Owner: `coreruleset/coreruleset@96d9f99:crs-setup.conf.example`, `rules/REQUEST-949-BLOCKING-EVALUATION.conf`, `rules/RESPONSE-959-BLOCKING-EVALUATION.conf`, `rules/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf.example`. Official install docs: blocking mode → **Error 403**.

Extracts: `.sources/crs-setup.conf.example.md`, `.sources/request-949-blocking-evaluation.conf.md`, `.sources/response-999-exclusion-rules-after-crs.conf.example.md`, `.sources/crs-installation.md`

## Sidecar / Apache / docker vs a security block

`owasp/modsecurity-crs` images default to reverse proxy. `BACKEND` default is `http://localhost:80`. README: set `BACKEND` to a listening server or “nothing useful will happen”. Apache variant: ModSecurity **v2.9.x** on httpd. Nginx variant: ModSecurity **v3.x**. Image verification treats a CRS attack request as **403**. Nginx templates add CORS headers on **403** and map `error_page 500 502 503 504` to `/50x.html`.

Owner: `coreruleset/modsecurity-crs-docker@5e3cda3:README.md`, `apache/conf/extra/httpd-vhosts.conf`, `tests/verify-image.sh`, `nginx/templates/includes/location_common.conf.template`.

Extracts: `.sources/crs-docker-readme.md`, `.sources/httpd-vhosts.conf.md`, `.sources/verify-image.sh.md`, `.sources/location_common.conf.template.md`

Apache `mod_proxy_http` (2.4.58) when the **origin** fails:

| Condition | Code the source returns |
| --- | --- |
| `ap_proxy_connect_backend` fails (BACKEND down / refused) | `HTTP_SERVICE_UNAVAILABLE` **503** |
| Error reading from remote / corrupt status line | `HTTP_BAD_GATEWAY` **502** |
| First request on the connection fails in a “fishy” way | `HTTP_INTERNAL_SERVER_ERROR` **500** |
| No valid protocol handler | `HTTP_INTERNAL_SERVER_ERROR` **500** (`mod_proxy.c`) |

`ProxyTimeout` is documented as failing the request on a hung backend; the HTTP proxy module sets a `proxy_timedout` note and often surfaces that as 502/503 rather than naming 504. AJP/FCGI connectors do return `HTTP_GATEWAY_TIME_OUT` **504** on `APR_STATUS_IS_TIMEUP`. Constants: `httpd.h` 502 / 503 / 504.

Owner: [mod_proxy](https://httpd.apache.org/docs/2.4/mod/mod_proxy.html) (`ProxyPass` retry / worker error state, `ProxyTimeout`, `ProxyErrorOverride`); `apache/httpd@2.4.58:modules/proxy/mod_proxy_http.c`, `modules/proxy/mod_proxy.c`, `include/httpd.h`.

Extracts: `.sources/httpd-mod_proxy.md`, `.sources/mod_proxy_http.c.md`, `.sources/httpd.h.md`

CRS-docker Apache sets `ProxyErrorOverride ${PROXY_ERROR_OVERRIDE}` (README default **on**). Official `ProxyErrorOverride` can rewrite proxied 4xx/5xx (example list includes 403, 500, 502, 503, 504). That changes the **body**, not the fact that those codes are error-class.

Nginx official `proxy_next_upstream` treats `error`, `timeout`, and `invalid_header` as unsuccessful communication with the proxied server. It lists `http_500` / `http_502` / `http_503` / `http_504` as upstream response codes, distinct from `http_403`.

Owner: [ngx_http_proxy_module — proxy_next_upstream](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_next_upstream).

Extract: `.sources/nginx-proxy-next-upstream.md`

## Implication for “500 means sidecar down”

Default CRS / image deny is **403**. A broken or unreachable `BACKEND` is typically **503** (Apache connect) or **502** (bad/missing upstream response). **500** appears both as a valid `deny,status:500`, as v2’s invalid-status deny, and as some Apache proxy failures. Do not treat every 5xx from the sidecar as “WAF down,” and do not treat 500 as exclusively infrastructure.
