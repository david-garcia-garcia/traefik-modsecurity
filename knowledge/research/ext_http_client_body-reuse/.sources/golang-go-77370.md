---
url: https://github.com/golang/go/issues/77370
title: net/http: drain response body after close
fetched: 2026-09-01
authority: official
---

Issue closed 2026-08-20 after Go 1.27 released.

When an HTTP/1 response body is closed, Go 1.27 reads unread body to EOF up to 256 KiB or 50 milliseconds, whichever is reached first.

Manual `io.Copy(io.Discard, resp.Body)` before Close was the prior recommendation; a large or streaming body needs a bound.
