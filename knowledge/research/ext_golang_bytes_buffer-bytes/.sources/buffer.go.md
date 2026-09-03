---
url: https://github.com/golang/go/blob/8bba868de983dd7bf55fcd121495ba8d6e2734e7/src/bytes/buffer.go
title: src/bytes/buffer.go Buffer.Bytes
fetched: 2026-09-03
authority: source
ref: golang/go@8bba868de983dd7bf55fcd121495ba8d6e2734e7:src/bytes/buffer.go
---

Tag `go1.21.13`. Product `go.mod` is `go 1.21`.

`Buffer` holds `buf []byte` and `off int`. Unread contents are `buf[off:len(buf)]`.

`Bytes` comment matches official docs (valid until next Read/Write/Reset/Truncate; slice aliases content). Body is `return b.buf[b.off:]` — no copy.

`Reset`: `b.buf = b.buf[:0]`; `b.off = 0`; retains capacity.

`tryGrowByReslice`: if `n <= cap(b.buf)-len(b.buf)`, reslices `b.buf` and writes into the existing array.

`Write` grows via that path when capacity remains, so a later Write can overwrite bytes still visible through a prior `Bytes()` slice.
