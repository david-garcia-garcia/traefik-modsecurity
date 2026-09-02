---
url: https://github.com/golang/go/blob/69801b25b9624c3a678ef87d30771861e7bba51f/src/net/http/request.go
title: net/http request.go Host promotion, NewRequest, Write
fetched: 2026-09-01
authority: source
ref: golang/go@69801b25b9624c3a678ef87d30771861e7bba51f:src/net/http/request.go
---

reqWriteExcludeHeader includes `"Host": true` with comment “not in Header map anyway”. Write uses writeSubset with this map, so a Host entry in Header is not written.

NewRequestWithContext (after Parse + removeEmptyPort):

```
req := &Request{
    ...
    Header: make(Header),
    Host:   u.Host,
}
```

write (HTTP/1.1 serialization):

- `host := r.Host`; if empty, `host = r.URL.Host` (error if URL is also nil).
- Punycode, ValidHostHeader, removeZone.
- Emits `Host: %s\r\n` from that `host` value, then writes Header minus reqWriteExcludeHeader.

readRequest:

- Parses MIME headers into req.Header.
- Rejects more than one Host header.
- `req.Host = req.URL.Host`; if empty, `req.Host = req.Header.get("Host")`.
- Absolute-form request-target: URL host wins; a Host line is ignored (RFC 7230 §5.3 comment in source).

ReadRequest: after readRequest, `delete(req.Header, "Host")`.

Also: `src/net/http/server.go` deletes `"Host"` from Header after validating the parsed request, then sets RemoteAddr.

Request.Clone copies the Host field via `*r2 = *r` and clones Header separately (so inbound Host stays on the field, not in the cloned map).
