---
url: https://pkg.go.dev/net/http
title: net/http Client.Do / Request / RoundTripper
fetched: 2026-09-03
authority: official
---

`func (c *Client) Do(req *Request) (*Response, error)` — sends an HTTP request and returns an HTTP response, following client policy (redirects, cookies, auth). A non-2xx status code does not cause an error.

If the returned error is nil, Response has a non-nil Body the user must close. If Body is not both read to EOF and closed, the Transport may not reuse a persistent TCP connection.

The request Body, if non-nil, will be closed by the underlying Transport, even on errors. The Body may be closed asynchronously after Do returns.

`Request.Body` (client): a nil body means no body. The HTTP Client's Transport is responsible for calling Close. Body must allow Read concurrently with Close; Close should unblock a Read waiting for input.

`NewRequestWithContext`: if the provided body is also an `io.Closer`, the returned `Request.Body` is that body and will be closed (possibly asynchronously) by Client methods Do, Post, and PostForm, and Transport.RoundTrip.

`RoundTripper.RoundTrip`: may read fields of the request in a separate goroutine. Callers should not mutate or reuse the request until the Response's Body has been closed. RoundTrip must always close the request body, including on errors, but depending on the implementation may do so in a separate goroutine even after RoundTrip returns. Callers wanting to reuse the body for subsequent requests must arrange to wait for that Close.
