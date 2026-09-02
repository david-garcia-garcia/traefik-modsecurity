---
url: https://pkg.go.dev/net#SplitHostPort
title: net SplitHostPort
fetched: 2026-09-01
authority: official
---

SplitHostPort splits "host:port", "host%zone:port", "[host]:port" or "[host%zone]:port" into host or host%zone and port.

Dial docs: if the host is a literal IPv6 address it must be enclosed in square brackets, as in "[2001:db8::1]:80" or "[fe80::1%zone]:80". JoinHostPort / SplitHostPort manipulate a pair of host and port in this form.

Implementation (`golang/go@go1.25.6:src/net/ipsock.go`): last colon starts the port; missing colon → "missing port in address". Bracketed form takes the bytes between `[` and `]` as host (no brackets in the return). Unbracketed host that still contains `:` → "too many colons in address".
