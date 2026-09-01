---
url: https://pkg.go.dev/net/http@go1.26.7#Request
title: net/http Request.ContentLength
fetched: 2026-09-01
authority: official
---

ContentLength records the length of the associated content.

The value -1 indicates that the length is unknown.

Values >= 0 indicate that the given number of bytes may be read from Body.

For client requests, a value of 0 with a non-nil Body is also treated as unknown.

TransferEncoding can usually be ignored; chunked encoding is automatically added and removed as necessary when sending and receiving requests.

For client requests, certain headers such as Content-Length and Connection are automatically written when needed and values in Header may be ignored. See Request.Write.

If Body is present, Content-Length is <= 0 and Request.TransferEncoding hasn't been set to "identity", Write adds Transfer-Encoding: chunked.
