---
url: https://pkg.go.dev/bytes#Buffer.Bytes
title: bytes.Buffer Bytes / Reset / Write
fetched: 2026-09-03
authority: official
---

`func (b *Buffer) Bytes() []byte`

Bytes returns a slice of length `b.Len()` holding the unread portion of the buffer. The slice is valid for use only until the next buffer modification (that is, only until the next call to a method like Buffer.Read, Buffer.Write, Buffer.Reset, or Buffer.Truncate). The slice aliases the buffer content at least until the next buffer modification, so immediate changes to the slice will affect the result of future reads.

`func (b *Buffer) Reset()`

Reset resets the buffer to be empty, but it retains the underlying storage for use by future writes. Reset is the same as Buffer.Truncate(0).

`func (b *Buffer) Write(p []byte) (n int, err error)`

Write appends the contents of p to the buffer, growing the buffer as needed. err is always nil unless the buffer becomes too large (`ErrTooLarge` panic).
