---
url: https://github.com/golang/go/blob/69801b25b9624c3a678ef87d30771861e7bba51f/src/net/http/h2_bundle.go
title: HTTP/2 Request.Host from :authority
fetched: 2026-09-01
authority: source
ref: golang/go@69801b25b9624c3a678ef87d30771861e7bba51f:src/net/http/h2_bundle.go
---

newWriterAndRequest: Authority from `:authority` pseudo-header. Regular header fields are copied into a new Header map. If Authority is empty, `rp.Authority = header.Get("Host")`.

newWriterAndRequestNoBody: `Host: rp.Authority` on the Request; `Header: rp.Header` unchanged (no delete of Host).

httpcommon.NewServerRequest (`src/net/http/internal/httpcommon/httpcommon.go`): deletes Trailer (and Expect when 100-continue); does not delete Host. CONNECT without :protocol uses Authority as URL.Host / RequestURI.
