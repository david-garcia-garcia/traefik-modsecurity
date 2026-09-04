---
url: https://github.com/golang/go/blob/8bba868de983dd7bf55fcd121495ba8d6e2734e7/src/net/http/client.go
title: src/net/http/client.go Client.Do
fetched: 2026-09-03
authority: source
ref: golang/go@8bba868de983dd7bf55fcd121495ba8d6e2734e7:src/net/http/client.go
---

Tag `go1.21.13`.

`Client.Do` comment at this pin: Do sends a request and returns a response. A non-2xx status is not an error. The request Body, if non-nil, will be closed by the underlying Transport, even on errors.

This pin does not include the later official sentence “The Body may be closed asynchronously after Do returns.” The persistConn writeLoop at the same tag already closes asynchronously.
