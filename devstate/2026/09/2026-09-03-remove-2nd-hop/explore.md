# Explore
IssueKey: 2026-09-03-remove-2nd-hop

## Concepts

```
Client → Traefik → plugin
                     ├─ hop 1: HTTP copy → CRS :8080
                     │              └─ hop 2 (today): ProxyPass/proxy_pass → dummy whoami
                     └─ hop 3: next → labeled whoami / app
```

Hop 2 is the CRS image acting as a reverse proxy (`BACKEND`). Dummy’s body is not the app. The plugin treats sidecar `< 300` as allow and `3xx`/`4xx` as a security block (`pkg/modsecurity/serve.go`). A sidecar `416` from dummy (or from a tiny inspect-only body + `Range`) is copied to the client as a block.

**Shadow WAF:** CRS inspects the copy and answers 200; Traefik `next` is the app.

**Inspect-only 200:** sidecar HTTP 200 after ModSecurity **request** phases, no origin fetch.

## Decisions

- Do **not** change `pkg/modsecurity/serve.go`. Allow `< 300` and 3xx/4xx-as-block stay.
- **Apache (pin 4.3.0-apache-alpine-202406090906):** drop `ProxyPass` / `ProxyPassReverse` / proxy knobs / websocket `[P]` to `${BACKEND_WS}` on `crs-apache/httpd-vhosts.conf`. Answer with the same pattern already used for `/healthz` in the image: `RewriteRule .* - [R=200,L]` + `ErrorDocument 200 "OK"`. Measured on live `/healthz`: GET allow 200, POST benign 200, URI SQLi 403, POST body `id=1 OR 1=1` 403. `rewrite_module` is loaded. `mod_lua` / `mod_cgi` exist on disk but are **not** loaded — do not add them.
- **Apache Range:** `/healthz` + `Range: bytes=10240-` is still **416** (2-byte body, not dummy). Dummy whoami is also ~360 bytes, so today’s 416 is “origin too small,” not unique to whoami. Overlay must `RequestHeader unset Range` (and `If-Range`) so the sidecar stays 200. Plugin cannot ignore 416 (out of scope).
- **Nginx `return 200`:** **abort.** Throwaway overlay of `proxy_backend.conf.template` → `return 200 'ok'` on pin `4.3.0-nginx-alpine-202406090906`: GET URI SQLi, path traversal, POST body SQLi, POST `UNION SELECT` were all **200**. CRS did not run (phase 1 and phase 2). Matches research inference (rewrite `return` before ModSecurity-nginx PREACCESS) and is worse than inferred: rewrite-phase rules also missed.
- **Nginx inspect-only:** same-container **drain-200**. Image has `nc`, not `httpd`/`python`. Mount an entrypoint.d script that listens on loopback and always writes HTTP 200 (ignore Range); set `BACKEND=http://127.0.0.1:<port>`. Keep `crs-nginx/realip.conf`. Overlay `proxy_backend.conf.template` only if needed to drop `Range` toward that drain. No extra compose service. No `return`.
- **Compose:** delete unlabeled `dummy` on `docker-compose.yml`, `docker-compose.local.yml`, `docker-compose.test.yml`, `docker-compose.test.nginx.yml`. Keep labeled whoami apps. Apache can drop `BACKEND=http://dummy`. Nginx sets `BACKEND` to the drain URL.
- **Docs:** rewrite README dummy/always-200 as shadow WAF. Integration usage still names dummy until compose changes.
- **Throughput before (this machine, Apache test compose, bombardier `-c 50 -d 15s`, `http://localhost:8000/protected`):**
  - GET: **5077 req/s** avg, latency **9.84 ms** avg (max 133.65 ms). 76072 × 2xx, **125 × 5xx**. Throughput 2.71 MB/s.
  - POST (`name=john&email=john@example.com`): **1098 req/s** avg, latency **45.47 ms** avg (max 198.37 ms). 12600 × 2xx, **3901 × 5xx**. Throughput 709.30 KB/s.
  After numbers are implement. Same tool, same flags, same URL.
- **Identity:** Traefik owns `X-Real-IP` / access-log `ClientHost`. CRS Apache `mod_remoteip` / nginx `real_ip` own audit `REMOTE_ADDR`. Keep existing overlays. Do not invent XFF in the plugin or in the inspect-only handler.

## Open questions

- Q: Does nginx `return 200` in `location /` still run CRS request-body inspection on pin 4.3.0-nginx?
  Decision: resolved — no. Live spike: URI probes and POST body probes returned 200. Do not ship `return`. Use drain-200.
  By: explore

- Q: Which Apache method-agnostic 200 still runs request phases on pin 4.3.0-apache?
  Decision: resolved — image `/healthz` `RewriteRule` `[R=200]` + `ErrorDocument 200`. URI and POST-body SQLi still 403; benign POST 200. Use that on `/`. Not Lua/CGI (modules not loaded).
  By: explore

- Q: Is today’s sidecar `416` only dummy/whoami?
  Decision: resolved — also Apache `/healthz` 2-byte 200 + `Range: bytes=10240-` → 416. Unset `Range`/`If-Range` on the inspect-only vhost (nginx drain must ignore Range too).
  By: explore

- Q: Exact nginx drain listen port and entrypoint script name?
  Decision: 127.0.0.1:18081 via crs-nginx/drain-origin.conf (second nginx server, max_ranges 0, return 200 after CRS proxy_pass). Not nc (serial) and not return on CRS location /.
  By: implement

- Q: Does the test suite drop dummy everywhere?
  Decision: no. Keep apache+whoami, nginx+whoami, apache+drain, nginx+drain. Benchmark all four in Pester (bombardier). Demo compose is drain-only.
  By: implement (human)

- Q: Who already owns client IP for WAF audit?
  Decision: resolved — Traefik `X-Real-IP` / `ClientHost`; CRS `RemoteIPHeader` / nginx `real_ip`. Reuse those overlays. Do not reconstruct from `RemoteAddr`.
  By: explore

- Q: Before-change allow-path throughput?
  Decision: resolved — GET 5077 req/s / 9.84 ms; POST 1098 req/s / 45.47 ms (bombardier -c 50 -d 15s, Apache `docker-compose.test.yml`, `/protected`). After still required on the delivery card.
  By: explore
