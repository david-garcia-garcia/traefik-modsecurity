---
url: https://pkg.go.dev/net/http#Request
title: net/http Request, NewRequestWithContext, Write
fetched: 2026-09-01
authority: official
---

Request.Header: if a server received `Host: example.com` plus other headers, the Header map example does not include Host. "For incoming requests, the Host header is promoted to the Request.Host field and removed from the Header map."

Request.Host (server): host on which the URL is sought. HTTP/1 (RFC 7230 §5.4): value of the Host header or the host name in the URL. HTTP/2: `:authority`. May be `host:port`.

Request.Host (client): optionally overrides the Host header to send. If empty, Request.Write uses URL.Host.

NewRequestWithContext: returns a Request suitable for Client.Do / Transport.RoundTrip. Points at Request docs for inbound vs outbound field differences.

Request.Write: consults Host, URL, Method, Header, ContentLength, TransferEncoding, Body. "Header values for Host, Content-Length, Transfer-Encoding, and Trailer are not used; these are derived from other Request fields."

Request.WriteProxy: writes a Host header using either r.Host or r.URL.Host.
