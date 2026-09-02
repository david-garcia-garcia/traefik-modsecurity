---
url: https://pkg.go.dev/net/http/httputil#ProxyRequest.SetURL
title: httputil ProxyRequest.SetURL
fetched: 2026-09-01
authority: official
---

SetURL routes the outbound request to the target scheme, host, and base path.

"SetURL rewrites the outbound Host header to match the target's host. To preserve the inbound request's Host header (the default behavior of NewSingleHostReverseProxy): set r.Out.Host = r.In.Host after SetURL."
