---
url: https://github.com/traefik/traefik/blob/237f13c677edb45ab696b7347b517e1f6b46b849/pkg/proxy/httputil/proxy.go
title: pkg/proxy/httputil/proxy.go
fetched: 2026-09-01
authority: source
ref: github.com/traefik/traefik@237f13c677edb45ab696b7347b517e1f6b46b849:pkg/proxy/httputil/proxy.go
---

Inspected from a shallow temp clone of traefik/traefik master; clone deleted after extract.

rewriteRequestBuilder: if isWebSocketUpgrade(pr.Out) then cleanWebSocketHeaders(pr.Out).

isWebSocketUpgrade: httpguts.HeaderValuesContainsToken(Connection, "Upgrade") && strings.EqualFold(req.Header.Get("Upgrade"), "websocket"). Whole-field EqualFold, not comma-tokenized.

cleanWebSocketHeaders recases Sec-Websocket-* map keys to Sec-WebSocket-Key / Extensions / Accept / Protocol / Version. Comment cites RFC 6455 page 20 (case-insensitive names; some servers want this spelling).
