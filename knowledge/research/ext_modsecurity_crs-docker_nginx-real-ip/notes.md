# CRS Docker nginx real_ip env

Official `owasp/modsecurity-crs` nginx images expose nginx `real_ip` through environment variables. They do **not** use Apache `REMOTEIP_*`.

This repo’s nginx pin is `owasp/modsecurity-crs:4.3.0-nginx-alpine-202406090906` (same CRS 4.3.0 date stamp as the Apache pin). Env names below are from the current CRS docker README; they match the nginx template contract (`REAL_IP_HEADER`, `SET_REAL_IP_FROM`, `REAL_IP_RECURSIVE`).

## Official: nginx ENV Variables

From [coreruleset/modsecurity-crs-docker README — Nginx ENV Variables](https://github.com/coreruleset/modsecurity-crs-docker#nginx-env-variables):

| Name | Official description | Default |
| --- | --- | --- |
| `REAL_IP_HEADER` | Name of the header containing the real IP value(s). Maps to [`real_ip_header`](http://nginx.org/en/docs/http/ngx_http_realip_module.html#real_ip_header). | `X-REAL-IP` |
| `SET_REAL_IP_FROM` | Comma-separated IP, CIDR, or UNIX domain socket addresses trusted to replace addresses in `REAL_IP_HEADER`. Maps to [`set_real_ip_from`](http://nginx.org/en/docs/http/ngx_http_realip_module.html#set_real_ip_from). | `127.0.0.1` |
| `REAL_IP_RECURSIVE` | Recursive replacement on addresses in `REAL_IP_HEADER` (`on` / `off`). Maps to [`real_ip_recursive`](http://nginx.org/en/docs/http/ngx_http_realip_module.html#real_ip_recursive). | `on` |
| `REAL_IP_PROXY_HEADER` | Header used to pass `$remote_addr` to the proxied backend (`proxy_set_header`). | `X-REAL-IP` |

`SET_REAL_IP_FROM` is **comma-separated**, not space-separated (unlike Apache `REMOTEIP_INT_PROXY`).

Default `127.0.0.1` does not trust a Docker-bridge Traefik hop. This repo’s nginx test compose sets RFC1918 ranges and `REAL_IP_HEADER=X-Real-IP` so nginx rewrites `REMOTE_ADDR` from Traefik’s `X-Real-Ip`.

Apache-only keys (`REMOTEIP_HEADER`, `REMOTEIP_INT_PROXY`) do not apply to nginx images.

## Official: audit log path

Shared ModSecurity ENV (Apache and nginx): `MODSEC_AUDIT_LOG` default `/dev/stdout`. The README example uses `/var/log/modsec_audit.log`. Both test compose files set that path so helpers can `docker exec cat` it.

## This repo

`docker-compose.test.nginx.yml` is the nginx CRS reference. Demo `docker-compose.yml` stays Apache.

Extract: `.sources/crs-docker-readme-nginx-env.md`
