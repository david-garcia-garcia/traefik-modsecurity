# bytes.Buffer Bytes alias

`bytes.Buffer.Bytes` returns a slice of the unread portion that **aliases** the Buffer backing array. The slice is valid only until the next Buffer modification (`Read`, `Write`, `Reset`, `Truncate`). Mutating the slice immediately changes what later Buffer reads see.

## Official contract

`Bytes() []byte` — “returns a slice of length `b.Len()` holding the unread portion of the buffer. The slice is valid for use only until the next buffer modification (that is, only until the next call to a method like `Buffer.Read`, `Buffer.Write`, `Buffer.Reset`, or `Buffer.Truncate`). The slice aliases the buffer content at least until the next buffer modification, so immediate changes to the slice will affect the result of future reads.”

`Reset` — empties the buffer but **retains** the underlying storage for future writes. Same as `Truncate(0)`.

`Write` — appends `p`, growing as needed.

Owner: [bytes.Buffer.Bytes](https://pkg.go.dev/bytes#Buffer.Bytes), [Reset](https://pkg.go.dev/bytes#Buffer.Reset), [Write](https://pkg.go.dev/bytes#Buffer.Write).

Extract: `.sources/pkg-go-dev-bytes-buffer.md`

## Implementation (go1.21.13)

Pinned: `golang/go@8bba868de983dd7bf55fcd121495ba8d6e2734e7` (`go1.21.13`). Product `go.mod` is `go 1.21`.

```
func (b *Buffer) Bytes() []byte { return b.buf[b.off:] }
```

No copy. `buf` is the backing array; unread bytes are `buf[off:len]`.

`Reset` sets `buf = buf[:0]`, `off = 0`. Capacity is kept. The next `Write` grows by reslice into that same array when capacity allows (`tryGrowByReslice`), so it can overwrite the bytes a previous `Bytes()` slice still points at.

A caller that hands `buf.Bytes()` to something that still `Read`s after `Reset`/`Write` (for example `http.Request.Body` still being copied by `persistConn.writeLoop`) races on that array.

Owner: `golang/go@8bba868de983dd7bf55fcd121495ba8d6e2734e7:src/bytes/buffer.go` (`Bytes`, `Reset`, `tryGrowByReslice`).

Extract: `.sources/buffer.go.md`
