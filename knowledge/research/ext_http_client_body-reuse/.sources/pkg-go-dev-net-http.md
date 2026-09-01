---
url: https://pkg.go.dev/net/http#Client.Do
title: net/http Client.Do / Response.Body
fetched: 2026-09-01
authority: official
---

If the Body is not both read to EOF and closed, the Client's underlying RoundTripper (typically Transport) may not be able to re-use a persistent TCP connection for a subsequent keep-alive request.

Transport will automatically try to read a Response Body to EOF asynchronously up to a conservative limit when a Body is closed (docs text; Go 1.27 implements 256 KiB / 50 ms).

The default HTTP client's Transport may not reuse HTTP/1.x keep-alive TCP connections if the Body is not read to completion and closed; closing the body will also cause the body to be read to completion asynchronously, up to a conservative limit.
