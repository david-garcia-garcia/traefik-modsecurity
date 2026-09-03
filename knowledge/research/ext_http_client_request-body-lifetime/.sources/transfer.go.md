---
url: https://github.com/golang/go/blob/8bba868de983dd7bf55fcd121495ba8d6e2734e7/src/net/http/transfer.go
title: src/net/http/transfer.go transferWriter.writeBody
fetched: 2026-09-03
authority: source
ref: golang/go@8bba868de983dd7bf55fcd121495ba8d6e2734e7:src/net/http/transfer.go
---

Tag `go1.21.13`.

`writeBody`: `doBodyCopy` is `io.Copy(dst, src)` from the request Body (chunked, unknown length, or `LimitReader` plus discard of extras). Then `BodyCloser.Close()`. A deferred Close runs if that path did not already close.

A Write error from a server that closed the connection surfaces here while `writeLoop` is still on this goroutine. Close of `Request.Body` still runs.
