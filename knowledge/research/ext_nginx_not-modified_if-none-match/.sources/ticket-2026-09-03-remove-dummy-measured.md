---
url: devstate/2026/09/2026-09-03-remove-dummy/explore.md
title: 2026-09-03-remove-dummy explore measurements
fetched: 2026-09-03
authority: ticket
---

Measured 2026-09-03 on this worktree.

Nginx drain: `If-None-Match: *` is 304 on the loopback origin (`return 200` on 127.0.0.1:18081), the public sidecar `:8080` (`proxy_pass` to that origin), and Traefik.

Throwaway `nginx:alpine`: `etag off;` plus `if_modified_since off;` still 304. `error_page 304 =200` still 304. `return 204` stays 204.

Two-server throwaway: `proxy_set_header If-None-Match "";` and `proxy_set_header If-Modified-Since "";` then `proxy_pass` to `return 200` stays 200.

CRS request phases run before `proxy_pass` on the public server, so clearing those headers on `proxy_pass` still lets ModSecurity see the client header.

Product choice recorded there: do not use 204 as the drain allow status; keep 200 and strip conditionals on `proxy_pass`.
