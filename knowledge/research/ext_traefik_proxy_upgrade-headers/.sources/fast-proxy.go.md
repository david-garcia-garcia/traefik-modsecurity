---
url: https://github.com/traefik/traefik/blob/237f13c677edb45ab696b7347b517e1f6b46b849/pkg/proxy/fast/proxy.go
title: pkg/proxy/fast/proxy.go and upgrade.go
fetched: 2026-09-01
authority: source
ref: github.com/traefik/traefik@237f13c677edb45ab696b7347b517e1f6b46b849:pkg/proxy/fast/proxy.go
---

Inspected from a shallow temp clone of traefik/traefik master; clone deleted after extract.

hopHeaders includes Connection, Proxy-Connection, Keep-Alive, Proxy-Authenticate, Proxy-Authorization, Te, Trailer, Transfer-Encoding, Upgrade.

Outbound path: copy request headers → removeConnectionHeaders (split Connection on comma, DelBytes each token) → Del every hopHeaders name → upgradeType(req.Header). If reqUpType != "", Set Connection=Upgrade and Upgrade=reqUpType. If EqualFold(reqUpType, "websocket"), cleanWebSocketHeaders (re-case Sec-WebSocket-*).

upgrade.go upgradeType: if !httpguts.HeaderValuesContainsToken(h["Connection"], "Upgrade") return "". Else return h.Get("Upgrade").
