---
url: https://github.com/golang/go/blob/69801b25b9624c3a678ef87d30771861e7bba51f/src/net/ipsock.go
title: net SplitHostPort, JoinHostPort, TCPAddr.String
fetched: 2026-09-01
authority: source
ref: golang/go@69801b25b9624c3a678ef87d30771861e7bba51f:src/net/ipsock.go
---

SplitHostPort: last `:` is the port separator. If hostport starts with `[`, host is the bytes between `[` and `]` (brackets stripped). Unbracketed host that still contains `:` → "too many colons in address". Missing `:` → "missing port in address".

JoinHostPort: if host contains `:`, return `"[" + host + "]:" + port`; else `host + ":" + port`.

TCPAddr.String (`src/net/tcpsock.go`): `JoinHostPort(ip, port)`, or `JoinHostPort(ip+"%"+zone, port)` when Zone is set. IPv6 therefore serializes as `[addr]:port` or `[addr%zone]:port`.

HTTP server (`src/net/http/server.go`): `c.remoteAddr = ra.String()` from `rwc.RemoteAddr()`; that string is copied onto `req.RemoteAddr`.
