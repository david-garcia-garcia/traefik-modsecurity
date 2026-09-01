## 1. Sidecar client identity

- [ ] 1.1 Add `appendPeerToXForwardedFor` in `pkg/modsecurity` that implements the ReverseProxy Director join (`SplitHostPort`, join prior values with `", "`, skip on parse failure)
- [ ] 1.2 After the sidecar header copy in `ServeHTTP`, set `proxyReq.Host = req.Host` and call the helper with `req.RemoteAddr`
- [ ] 1.3 Add tests that assert mock WAF `r.Host` and `X-Forwarded-For` for empty prior, existing chain, IPv6 `[addr]:port`, and unparseable `RemoteAddr`
- [ ] 1.4 Run `go test ./...` and record the result
