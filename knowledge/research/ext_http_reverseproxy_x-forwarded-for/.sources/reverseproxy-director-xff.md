---
url: https://cs.opensource.google/go/go/+/refs/tags/go1.25.6:src/net/http/httputil/reverseproxy.go
title: httputil.ReverseProxy Director X-Forwarded-For
fetched: 2026-09-01
authority: source
ref: go@go1.25.6:src/net/http/httputil/reverseproxy.go
---

Director path (Rewrite == nil): SplitHostPort(req.RemoteAddr); on success join prior X-Forwarded-For values with ", " then Set; on failure leave the header alone.

omit := ok && prior == nil (Issue 38079): present-but-nil means do not populate X-Forwarded-For.

SetXForwarded: same join on success; Del X-Forwarded-For on parse failure; also sets X-Forwarded-Host and X-Forwarded-Proto.
