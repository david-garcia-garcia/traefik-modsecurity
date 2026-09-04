---
url: https://github.com/golang/go/blob/8bba868de983dd7bf55fcd121495ba8d6e2734e7/src/net/http/transport.go
title: src/net/http/transport.go persistConn writeLoop / roundTrip / readLoop
fetched: 2026-09-03
authority: source
ref: golang/go@8bba868de983dd7bf55fcd121495ba8d6e2734e7:src/net/http/transport.go
---

Tag `go1.21.13`. Product `go.mod` is `go 1.21`.

`persistConn` (HTTP/1): `writech` is written by `roundTrip` and read by `writeLoop`. `reqch` is written by `roundTrip` and read by `readLoop`. `writeErrCh` passes the request-write error from `writeLoop` to `readLoop` / the response-body reader for reuse (Issue 7569).

`writeLoop`: `wr.req.Request.write(...)` then `Flush`. On error it `pc.close`s and returns. It sends the write error on `writeErrCh` and `wr.ch`.

`roundTrip` comment: “Write the request concurrently with waiting for a response, in case the server decides to reply before reading our full request body.” It does `pc.writech <- writeRequest{...}` then `pc.reqch <- requestAndChan{...}` and selects. `case re := <-resc` with `re.err == nil` returns `re.res, nil` without waiting for the write to finish.

`readLoop`: `readResponse` / `ReadResponse`, then `rc.ch <- responseAndError{res: resp}`. That unblocks `roundTrip` after headers, not after the caller drains `Response.Body`. With a body, it then waits on `waitForBodyRead`.

`wroteRequest`: common case write already finished. Rare / Issue 7569: “the writer is still writing (or stalled), but the server has already replied.” Wait up to `maxWriteWaitBeforeConnReuse` (50 ms); if the write is still outstanding, return false so the connection is not reused.
