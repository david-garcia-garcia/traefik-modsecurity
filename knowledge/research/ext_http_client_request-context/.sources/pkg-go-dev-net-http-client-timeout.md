---
url: https://pkg.go.dev/net/http#Client.Timeout
title: net/http Client.Timeout
fetched: 2026-09-02
authority: official
---

Timeout is a time limit for requests made by this Client. It includes connection time, redirects, and reading the response body.

A Timeout of zero means no timeout.

The Client cancels requests to the underlying Transport as if the Request's Context ended.

Do errors are `*url.Error`. `url.Error.Timeout()` is true when the request timed out.
