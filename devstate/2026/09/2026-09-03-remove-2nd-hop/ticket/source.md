# inspect-only CRS sidecar (drop dummy hop)

Local spec. Caller extras (chat, 2026-09-03):

- Issue slug: remove-2nd-hop. IssueKey: 2026-09-03-remove-2nd-hop.
- Use a dedicated git worktree.
- Benchmark throughput BEFORE and AFTER the change. Put any improvement on the delivery card.

Source brief: `modsecissues/inspect-only-sidecar.md` (scratch from chat explore, 2026-09-03).

---

# Implementer brief: inspect-only CRS sidecar (drop dummy hop)

Scratch from chat explore (2026-09-03). Not an OpenSpec change yet. Start **sbs-dev-prepare** with a human `IssueKey` before product commits if you are in the eight-phase pipeline.

**Goal:** stop the OWASP CRS container from `ProxyPass` / `proxy_pass` to a second `dummy` (whoami) service. After ModSecurity **request** phases, the sidecar itself answers **HTTP 200**. Traefik `next` remains the real app.

This is **compose + CRS overlay**, not a plugin feature. Do **not** change `pkg/modsecurity/serve.go` for this.

---

## Why

Allow path today:

```
Client → Traefik → plugin
                     ├─ hop 1 (required): HTTP copy → CRS :8080
                     │                         └─ hop 2 (drop this): ProxyPass → dummy whoami
                     └─ hop 3 (required): next → real app
```

Hop 1 is the product (Yaegi cannot load libmodsecurity). Hop 2 is only the stock CRS Docker image (`BACKEND` → Apache `ProxyPass` / nginx `proxy_pass`). Dummy’s response is **not** the real app, so CRS phase 4 already does not protect the backend. Hop 2 still costs latency and causes:

| Upstream issue (other repo) | How dummy hurts |
|-----------------------------|-----------------|
| #23 | Apache `AH01084` passing body to whoami; whoami echoes the full request |
| #25 | Apache `416` when `Range` is larger than whoami; we copy sidecar 4xx as a block |
| #27 | Operators confuse dummy with Traefik’s backend |

Plugin keep-alive (#2) is already fixed (`discardSidecarBody`). This brief does **not** add bombardier benches and does **not** raise `maxBodySizeBytes` (#20).

---

## Do not

- Add a plugin `Config` knob. `ServeHTTP` already treats sidecar `< 300` as allow.
- Point `BACKEND` at Traefik or at the real app (second production request; app 3xx/4xx become WAF blocks — #19).
- Set `BACKEND=http://127.0.0.1:8080` (loop).
- Rely on omitting `BACKEND` — image default is `http://localhost:80` and still proxies.
- Rely on `MODSEC_RULE_ENGINE=DetectionOnly` — that does not remove `ProxyPass`.
- Use a static Apache `DocumentRoot` / `index.html` as the 200 handler — **POST often 405**. This plugin copies sidecar `3xx`/`4xx` as a **security block**. POST/PUT must return **2xx**.
- Drop Traefik `X-Real-IP` trust (`REMOTEIP_*` / nginx `real_ip`). Existing client-IP audit tests depend on it.
- Remove labeled whoami **apps** (`website-with-waf`, `whoami-protected`, …). Only the unlabeled **`dummy` CRS origin** goes away.

---

## How CRS Docker expects overlays

Stock image is a reverse proxy. Official escape hatch is **file overlays**, not an env flag.

**Nginx** (CRS Docker README): mount templates under `/etc/nginx/templates/` so `20-envsubst-on-templates.sh` still runs. Files in `templates/` keep subdirectory layout.

Relevant stock files (image `main` / same shape on our 4.3.0 pin):

- `nginx/templates/conf.d/modsecurity.conf.template` — `modsecurity on;` at **http** level (keep).
- `nginx/templates/conf.d/default.conf.template` — `location /` includes `includes/proxy_backend.conf`.
- `nginx/templates/includes/proxy_backend.conf.template` — `proxy_pass ${BACKEND};` plus `real_ip_*` (too late for CRS on 4.3.0 nginx pin).
- `location /healthz` already `return 200 "OK"` without proxy.

**Apache:** vhost is `/usr/local/apache2/conf/extra/httpd-vhosts.conf`. This repo **already mounts** `crs-apache/httpd-vhosts.conf` (RemoteIPHeader X-Real-IP). That overlay still has `ProxyPass / ${BACKEND}/ disablereuse=on`. Edit **that file**; do not add a parallel vhost.

Pinned images in compose today:

- Apache: `owasp/modsecurity-crs:4.3.0-apache-alpine-202406090906`
- Nginx test: `owasp/modsecurity-crs:4.3.0-nginx-alpine-202406090906`

---

## Intended change

### 1. Nginx overlay (smallest)

New file, e.g. `crs-nginx/proxy_backend.conf.template` (name to match the image template), mounted to:

`/etc/nginx/templates/includes/proxy_backend.conf.template`

Replace `proxy_pass ${BACKEND};` with a method-agnostic 2xx, e.g.:

```
default_type text/plain;
return 200 'ok';
```

Keep cors include via `default.conf` (do not drop `include includes/cors.conf`).

**Keep** existing `crs-nginx/realip.conf` → `/etc/nginx/conf.d/zz-realip.conf`. On 4.3.0, `real_ip` inside `proxy_backend.conf` is **too late** for ModSecurity. If the new template still contains `real_ip_*`, http-level overlay still wins; do not remove `zz-realip.conf`.

Mount this overlay on **every** nginx compose that today sets `BACKEND=http://dummy` (`docker-compose.test.nginx.yml` at minimum).

### 2. Apache overlay

Edit `crs-apache/httpd-vhosts.conf`:

- Remove `ProxyPass` / `ProxyPassReverse` / `ProxyErrorOverride` / `ProxyTimeout` / `ProxyPreserveHost` / `ProxyRequests` if unused.
- Remove websocket `RewriteRule` `[P]` to `${BACKEND_WS}`.
- Leave `RemoteIPHeader X-Real-IP`, `RemoteIPInternalProxy ${REMOTEIP_INT_PROXY}`, Unique-ID / X-Forwarded-Proto request headers as they are (client-IP contract).
- Add a **method-agnostic HTTP 200** after request processing (Lua `DONE`, CGI that discards stdin, or equivalent). **Not** a static file.

`${BACKEND}` may remain in the environment unused, or compose can drop `BACKEND=` once nothing interpolates it. Do not leave a `ProxyPass` that still needs dummy.

### 3. Compose

On Apache and nginx compose files that have `dummy:` + `BACKEND=http://dummy`:

- Delete the **`dummy` service** (unlabeled `traefik/whoami` used only as CRS origin).
- Drop `BACKEND=http://dummy` if the overlay no longer references it.
- Keep `waf` healthchecks working: nginx test compose currently probes `http://127.0.0.1:8080/` (not `/healthz`). Inspect-only `return 200` on `/` satisfies that.

Files that set dummy today: `docker-compose.yml`, `docker-compose.local.yml`, `docker-compose.test.yml`, `docker-compose.test.nginx.yml` (and nginx twin if any).

### 4. Docs

README “dummy so the WAF forwards and always 200”: rewrite as **shadow WAF** — plugin copies the request to CRS; CRS inspects and 200s; Traefik `next` is the app. Language already in `knowledge/devdocs/core_plugin_middleware.md` (`sidecar request` vs `next`). Close the #27 mix-up.

---

## Must prove (or the change is wrong)

Run against live CRS (Pester / curl through Traefik **and** curl straight at `waf:8080`):

1. **Allow:** benign GET and **POST with a small body** → sidecar **200**, plugin calls `next`, app body/status unchanged.
2. **Phase 1 block:** classic CRS probe in the **URI/query** (existing integration attack path) → sidecar **403** (or configured deny), `next` not called.
3. **Phase 2 block (gate):** CRS probe in the **POST body** (not only the URL). If this becomes 200, nginx `return` skipped request-body inspection — **abort `return`**, use a handler that runs after access (or a loopback drain-200). Apache static 405 also fails this.
4. **Range:** `Range: bytes=10240-` on a small GET must **not** become sidecar **416** (that was dummy/whoami). Expect 200 from sidecar, then backend 206/200 as today.
5. **Client IP:** existing audit `REMOTE_ADDR` == Traefik `ClientHost` tests still pass (X-Real-IP overlays).
6. **No dummy:** `docker compose ps` has no `dummy` service; `BACKEND` not required for a 200.

Existing Go unit tests mock the sidecar; they will not catch a broken overlay. Integration suite is the authority.

---

## Fallback if `return 200` skips body rules

Same-container **drain-200** on loopback (tiny process, `BACKEND=http://127.0.0.1:<internal>`), still **no** extra compose service. That is worse than inspect-only but still removes whoami and #23 echo. Document why `return` failed (phase 2).

---

## Out of scope (do not sneak in)

- Plugin `maxBodySizeBytes` default / README 5 MB lie (#20)
- Durable allow-path CORS header test / Yaegi (#29)
- Bombardier vs upstream #2 (no `Benchmark*` in this tree)
- In-process libmodsecurity
- Changing 3xx/4xx-as-block in `serve.go`

---

## Suggested first spike (before a large compose sweep)

1. Overlay nginx `proxy_backend.conf.template` only on `docker-compose.test.nginx.yml`.
2. Prove gates 1–3 (especially **POST body** CRS hit) with `curl` at `waf:8080`.
3. If phase 2 holds, mirror Apache overlay + drop `dummy` on Apache compose; run Pester.
4. Then demo `docker-compose.yml` / `docker-compose.local.yml`.
