---
url: https://github.com/traefik/traefik/blob/237f13c677edb45ab696b7347b517e1f6b46b849/pkg/middlewares/forwardedheaders/forwarded_header.go
title: pkg/middlewares/forwardedheaders/forwarded_header.go
fetched: 2026-09-01
authority: source
ref: github.com/traefik/traefik@237f13c677edb45ab696b7347b517e1f6b46b849:pkg/middlewares/forwardedheaders/forwarded_header.go
---

Inspected from a shallow temp clone of traefik/traefik master; clone deleted after extract.

ServeHTTP: rewrite X-Forwarded-*, then removeConnectionHeaders, then next.

removeConnectionHeaders:

- If httpguts.HeaderValuesContainsToken(req.Header["Connection"], "Upgrade"), save Get("Upgrade") as reqUpType.
- For each Connection field, strings.SplitSeq on comma, textproto.TrimString. Canonicalize. Skip Traefik-managed X- headers. If on forwardedHeaders.connection allow-list, keep the name on the rewritten Connection list. Else delete(req.Header, key).
- If reqUpType != "", append "Upgrade" to the kept list and Set("Upgrade", reqUpType).
- Set Connection to the kept names, or Del("Connection").

isWebsocketRequest (X-Forwarded-Proto ws/wss only): comma-split Get(name), EqualFold(trim(token), value) for Connection=upgrade and Upgrade=websocket. No method or Sec-WebSocket-* check.

forwarded_header_test.go TestConnection "remove and upgrade": headers Upgrade=test, Foo=bar, Connection=upgrade,foo → expected Upgrade=test, Connection=Upgrade. Not WebSocket-specific.

Test_isWebsocketRequest: Connection token upgrade in any comma position is true; Connection without upgrade is false; Upgrade foo,bar,websocket is true.
