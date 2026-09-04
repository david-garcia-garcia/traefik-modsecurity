---
url: https://github.com/golang/go/blob/8bba868de983dd7bf55fcd121495ba8d6e2734e7/src/net/http/request.go
title: src/net/http/request.go Request.Body / write / closeBody
fetched: 2026-09-03
authority: source
ref: golang/go@8bba868de983dd7bf55fcd121495ba8d6e2734e7:src/net/http/request.go
---

Tag `go1.21.13`.

`Request.Body` comment (client): Transport is responsible for calling Close. Body must allow Read concurrently with Close; Close should unblock a waiting Read.

`Request.write` (used by `persistConn.writeLoop`): defer `closeBody` unless the body-write path already closed it. After headers, `tw.writeBody(w)`. Errors from reading the user Body are wrapped as `requestBodyReadError`.

`closeBody`: `r.Body.Close()` when Body is non-nil.
