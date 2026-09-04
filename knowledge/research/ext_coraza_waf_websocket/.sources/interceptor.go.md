---
url: https://github.com/corazawaf/coraza/blob/5c9a34ab5b860479f18fa237bea7a05c6c3f9d93/http/interceptor.go
title: Coraza rwInterceptor hijack / 101 handling
fetched: 2026-09-03
authority: source
ref: corazawaf/coraza@5c9a34ab5b860479f18fa237bea7a05c6c3f9d93:http/interceptor.go
---

hijackerTracker.Hijack marks interceptor.isHijacked on success so response processing is skipped.

WriteHeader: still runs ProcessResponseHeaders. For status 101 Switching Protocols, flush headers immediately because there will be no HTTP response body.

processResponse: if isHijacked, return nil (do not write HTTP body to the taken-over connection).

interceptor_test.go TestWAFNotBypassedAfterWebSocketUpgrade: after a real upgrade + frame echo on one TCP connection, a later HTTP request with a deny-matching payload is still blocked; a benign request is allowed.
