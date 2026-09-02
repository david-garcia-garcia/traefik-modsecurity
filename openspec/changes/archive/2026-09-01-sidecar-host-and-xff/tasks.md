## 1. Sidecar client identity

- [x] 1.1 Add `appendPeerToXForwardedFor` in `pkg/modsecurity` that implements the ReverseProxy Director join (`SplitHostPort`, join prior values with `", "`, skip on parse failure)
- [x] 1.2 After the sidecar header copy in `ServeHTTP`, set `proxyReq.Host = req.Host` and call the helper with `req.RemoteAddr`
- [x] 1.3 Add tests that assert mock WAF `r.Host` and `X-Forwarded-For` for empty prior, existing chain, IPv6 `[addr]:port`, and unparseable `RemoteAddr`
- [x] 1.4 Run `go test ./...` and record the result — pass (`ok` root, `pkg/health`, `pkg/modsecurity`, `pkg/reclaim`)
