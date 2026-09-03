---
url: https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/waf/
title: Coraza Web Application Firewall - Traefik
fetched: 2026-09-03
authority: official
---

Hub-only middleware. Native Hub Coraza vs WASM Coraza plugin on open-source Traefik Proxy.

Examples are HTTP SecLang: deny REQUEST_URI /admin; CRS with allowed_methods GET and REQUEST-911 / REQUEST-949 includes.

Configuration options: directives (required), crsEnabled (default false).

The page does not mention WebSocket, Upgrade, Connection, or 101.
