---
url: https://pkg.go.dev/net/http#MaxBytesReader
title: net/http MaxBytesReader
fetched: 2026-09-03
authority: official
---

MaxBytesReader is similar to io.LimitReader but is intended for limiting the size of incoming request bodies. In contrast to io.LimitReader, MaxBytesReader's result is a ReadCloser, returns a non-nil error of type *MaxBytesError for a Read beyond the limit, and closes the underlying reader when its Close method is called.

MaxBytesReader prevents clients from accidentally or maliciously sending a large request and wasting server resources. If possible, it tells the ResponseWriter to close the connection after the limit has been reached.

MaxBytesError is returned by MaxBytesReader when its read limit is exceeded. Error() text is "http: request body too large".
