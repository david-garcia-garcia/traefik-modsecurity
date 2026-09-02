---
url: https://pkg.go.dev/net/http/httputil#ReverseProxy
title: net/http/httputil ReverseProxy and SetXForwarded
fetched: 2026-09-01
authority: official
---

SetXForwarded (added go1.20): sets X-Forwarded-For, X-Forwarded-Host, and X-Forwarded-Proto on the outbound request.

- X-Forwarded-For = client IP. If outbound already has X-Forwarded-For, append the client IP.
- X-Forwarded-Host = host name requested by the client.
- X-Forwarded-Proto = "http" or "https" from whether the inbound request was TLS.

To append to the inbound X-Forwarded-For (default Director behavior), copy `r.Out.Header["X-Forwarded-For"] = r.In.Header["X-Forwarded-For"]` before SetXForwarded.

Rewrite: Forwarded, X-Forwarded, X-Forwarded-Host, and X-Forwarded-Proto are removed from the outbound request before Rewrite is called. See SetXForwarded.

Director: "By default, the X-Forwarded-For header is set to the value of the client IP address. If an X-Forwarded-For header already exists, the client IP is appended to the existing values. As a special case, if the header exists in the Request.Header map but has a nil value (such as when set by the Director func), the X-Forwarded-For header is not modified. To prevent IP spoofing, be sure to delete any pre-existing X-Forwarded-For header coming from the client or an untrusted proxy."

NewSingleHostReverseProxy: returns a ReverseProxy using the deprecated Director function; this proxy preserves X-Forwarded-* headers sent by the client.
