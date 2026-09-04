# Client.Do request-body lifetime

`Client.Do` can return a `*Response` as soon as the Transport has parsed response headers. On HTTP/1, `persistConn.writeLoop` may still `Read` `Request.Body` on another goroutine. The Transport closes that body, possibly after `Do` returns.

This is not [HTTP/1 client body reuse](../ext_http_client_body-reuse/) (that folder is `Response.Body` and keep-alive).

## Official contract

`Do` sends the request and returns a response. A non-2xx status is not an error. The request `Body`, if non-nil, is closed by the underlying Transport, even on errors. Current docs add: the Body may be closed asynchronously after `Do` returns.

Owner: [net/http Client.Do](https://pkg.go.dev/net/http#Client.Do).

`Request.Body` on a client request is closed by the Transport. `Body` must allow `Read` concurrent with `Close`; `Close` must unblock a waiting `Read`.

Owner: [net/http Request](https://pkg.go.dev/net/http#Request).

`NewRequestWithContext`: if the provided body is an `io.Closer`, Client `Do` / `Post` / `PostForm` and `Transport.RoundTrip` close it, possibly asynchronously.

Owner: [net/http NewRequestWithContext](https://pkg.go.dev/net/http#NewRequestWithContext).

`RoundTripper.RoundTrip` may read request fields on a separate goroutine. It must always close the body, including on errors, and may do so in a separate goroutine after `RoundTrip` returns. Callers that want to reuse the body must wait for that `Close`.

Owner: [net/http RoundTripper](https://pkg.go.dev/net/http#RoundTripper).

Extract: `.sources/pkg-go-dev-net-http.md`

## HTTP/1 write vs read (go1.21.13)

Pinned: `golang/go@8bba868de983dd7bf55fcd121495ba8d6e2734e7` (`go1.21.13`). Product `go.mod` is `go 1.21`.

`persistConn.roundTrip` writes the request concurrently with waiting for a response, “in case the server decides to reply before reading our full request body.” It sends a `writeRequest` on `pc.writech` and a `requestAndChan` on `pc.reqch`, then selects. A `resc` receive with a non-nil `*Response` returns that response immediately. It does not wait for `writeErrCh` first.

`persistConn.writeLoop` (other goroutine) receives `writeRequest` and calls `Request.write`, which reads `Request.Body` via `transferWriter.writeBody` (`io.Copy`). After the write it `Close`s the body.

`persistConn.readLoop` calls `readResponse` (`ReadResponse`) and then sends `responseAndError{res: resp}` on the unbuffered `rc.ch`. That is headers-plus-status, not a drained response body. `roundTrip` unblocks on that send.

`wroteRequest` (Issue 7569): the writer may still be writing (or stalled) after the server has already replied. In that case the connection is not reused (`maxWriteWaitBeforeConnReuse` is 50 ms in production).

Owner: `golang/go@8bba868de983dd7bf55fcd121495ba8d6e2734e7:src/net/http/transport.go` (`roundTrip`, `writeLoop`, `readLoop`, `wroteRequest`).

Extract: `.sources/transport.go.md`

`Request.write` defers `closeBody` (`Body.Close`) unless `writeBody` already closed it. `writeBody` `io.Copy`s from `Body` then `Close`s `BodyCloser`.

Owner: `…@8bba868…:src/net/http/request.go` (`write`, `closeBody`) and `…:src/net/http/transfer.go` (`writeBody`, `doBodyCopy`).

Extracts: `.sources/request.go.md`, `.sources/transfer.go.md`

go1.21.13 `Client.Do` comment says Transport closes the request Body even on errors. It does not yet say “closed asynchronously after Do returns.” Current official docs do. The writeLoop at this pin already closes asynchronously. Follow source for what 1.21 does; official agrees and is more explicit.

Extract: `.sources/client.go.md`

## Server 403 and a large unread POST

HTTP/1 allows the server to write a 403 (or any status) and close without reading the rest of a large POST. Then:

1. `readLoop` can parse those headers and deliver `*Response` to `roundTrip`. `Client.Do` returns that 403 (`err == nil`).
2. `writeLoop` may still be in `writeBody` / `io.Copy` from `Request.Body`.
3. The server close makes the remaining write fail (connection reset / broken pipe). `writeLoop` sends that error on `writeErrCh` and `pc.close`s. `Request.write` / `writeBody` still `Close` the request Body.
4. `wroteRequest` sees a late or failed write, so the connection is not put back in the idle pool.

`Do` returning is not a signal that `Request.Body` is idle. Mutating or pooling that body (or a `bytes.Buffer` behind it) before Transport `Close` is a race.

Owner: same Transport / Request / RoundTripper sources above. The 403-and-close sequence is the Issue 7569 path plus a write error after `pc.conn.Close`; it is not a separate official sentence.
