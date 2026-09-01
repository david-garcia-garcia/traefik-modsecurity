---
url: https://github.com/golang/go/blob/e3336a22ad3f0a90bd252c95d8b5544e02674205/src/net/http/request.go
title: net/http request.go Request.ContentLength and Write excludes
fetched: 2026-09-01
authority: source
ref: golang/go@e3336a22ad3f0a90bd252c95d8b5544e02674205:src/net/http/request.go
---

Request.ContentLength comment: records the length of the associated content. -1 indicates unknown. Values >= 0 indicate that many bytes may be read from Body. For client requests, 0 with a non-nil Body is also treated as unknown.

Header comment: for client requests, certain headers such as Content-Length and Connection are automatically written when needed and values in Header may be ignored.

reqWriteExcludeHeader includes Content-Length and Transfer-Encoding. Request.Write does not copy those from Header.

Write: if Body is present, Content-Length is <= 0, and TransferEncoding is not identity, Write adds Transfer-Encoding: chunked.

outgoingLength: Body nil or NoBody → 0; else if ContentLength != 0 return it; else return -1.
