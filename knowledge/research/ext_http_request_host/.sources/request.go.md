---
url: https://github.com/golang/go/blob/go1.25.6/src/net/http/request.go
title: src/net/http/request.go
fetched: 2026-09-01
authority: source
ref: golang/go@go1.25.6:src/net/http/request.go
---

Inspected from the local toolchain (`go1.25.6`, GOROOT `src/net/http/request.go`). Same path on the go1.25.6 tag.

reqWriteExcludeHeader includes `"Host": true` with comment "not in Header map anyway".

readRequest: reject more than one `Header["Host"]`. Then `req.Host = req.URL.Host`; if that is empty, `req.Host = req.Header.get("Host")` (absolute-form URL host wins over the Host line).

ReadRequest: after readRequest, `delete(req.Header, "Host")`.

NewRequestWithContext: parse URL, `u.Host = removeEmptyPort(u.Host)`, construct Request with `Header: make(Header)` and `Host: u.Host`.

write: `host := r.Host`; if empty, `host = r.URL.Host`; Punycode, ValidHostHeader, remove IPv6 zone; fprintf `Host: %s`. Does not read Header["Host"].
