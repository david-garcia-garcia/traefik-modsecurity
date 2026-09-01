# Request.ContentLength

On a server `*http.Request` that reached a handler, `ContentLength` is the framing length `net/http` already applied. It is not a second copy of `Header.Get("Content-Length")`. `-1` means the length is unknown. A chunked HTTP/1 request deletes `Content-Length` from the header map.

## `-1` is unknown

`Request.ContentLength` records the length of the associated content. **`-1` means the length is unknown.** Values `>= 0` mean that many bytes may be read from `Body`.

For **client** requests only, `0` with a non-nil `Body` is also treated as unknown (`outgoingLength` maps that case to `-1`, which becomes `Transfer-Encoding: chunked` on HTTP/1).

Owner: [net/http Request](https://pkg.go.dev/net/http@go1.26.7#Request) (`ContentLength` field). Same text in `golang/go@e3336a22` `src/net/http/request.go`.

Extract: `.sources/pkg-go-dev-net-http-request.md`

Pinned: `golang/go@e3336a22ad3f0a90bd252c95d8b5544e02674205` (tag `go1.26.7`) `src/net/http/request.go`.

## HTTP/1: chunked deletes `Content-Length`

`ReadRequest` / the HTTP/1 server call `readTransfer` → `parseTransferEncoding` → `fixLength`.

`parseTransferEncoding` **deletes** `Transfer-Encoding` from `Header`. HTTP/1.1 accepts only a single field whose value is `chunked` (ASCII case-insensitive). Anything else is an error (smuggling surface). HTTP/1.0 `Transfer-Encoding` is ignored.

Then `fixLength`, when `chunked` is true:

1. Still **rejects** an invalid `Content-Length` (non-digits, empty, `+3`, overflow). Chunked does not skip that check.
2. **`header.Del("Content-Length")`**.
3. **Returns `-1`**.

The handler therefore sees `ContentLength == -1`, `TransferEncoding == []string{"chunked"}`, and `Header.Get("Content-Length") == ""`. A client-supplied `Content-Length` on a chunked request does not survive on the header map.

Conflicting (different-valued) `Content-Length` fields are rejected before the handler. Identical duplicates are collapsed to one value, then removed if the request is chunked.

RFC 9112 §6.3 item 3: `Transfer-Encoding` overrides `Content-Length`; an intermediary that forwards MUST remove `Content-Length` first. Go accepts the chunked request after that removal instead of treating both headers as a hard error.

Owner: [RFC 9112 §6.3](https://www.rfc-editor.org/rfc/rfc9112.html#name-message-body-length). Implementation: `golang/go@e3336a22` `src/net/http/transfer.go` (`parseTransferEncoding`, `fixLength`).

Extracts: `.sources/rfc9112-message-body-length.md`, `.sources/transfer.go.md`

## HTTP/1: missing `Content-Length` is `0`, not `-1`

If the request is **not** chunked and has **no** `Content-Length`, `fixLength` deletes any empty CL slot and, for a request, **returns `0`**. RFC 9112 §6.3 item 7: a request with neither transfer coding nor a valid `Content-Length` has a message body length of zero.

So `ContentLength == 0` plus an empty `Header.Get("Content-Length")` means “no body”, not “unknown”. Unknown on HTTP/1 is chunked (`-1`) or an HTTP/1.0 close-delimited **response** (`-1`). A declared length keeps one sanitized `Content-Length` and sets `ContentLength` to that `int64`; `Body` is an `io.LimitReader` of that size.

Owner: [RFC 9112 §6.3](https://www.rfc-editor.org/rfc/rfc9112.html#name-message-body-length) item 7; `fixLength` request default in `transfer.go`.

## `ContentLength` vs `Header.Get("Content-Length")`

After a successful HTTP/1 parse, **`req.ContentLength` is the spoof-resistant framing length**. `Header.Get("Content-Length")` is leftover header text, not a second parser.

| Incoming HTTP/1 | `ContentLength` | `Header.Get("Content-Length")` |
| --- | --- | --- |
| `Transfer-Encoding: chunked` (optional CL stripped) | `-1` | `""` |
| Valid `Content-Length: N` | `N` | `"N"` |
| Neither header | `0` | `""` |
| Conflicting CLs, or invalid CL (also with chunked) | request rejected | never reaches handler |

`Atoi(Header.Get("Content-Length"))` on a chunked request is `0`. That is the wrong unknown signal. Use `req.ContentLength == -1`.

`Header.Get` is also the wrong knob on the **client** write path: `Request.Write` skips `Content-Length` / `Transfer-Encoding` in `Header` (`reqWriteExcludeHeader`) and derives the wire headers from `ContentLength`, `TransferEncoding`, and `Body`.

HTTP/2 has no `Transfer-Encoding`. If HEADERS does not end the stream and there is no `Content-Length`, `h2_bundle.go` sets `ContentLength = -1` and **does not** delete a header. The first `Content-Length` value is parsed when present; a non-numeric first value becomes `0` while the header map can still hold the raw field. Do not treat H1 and H2 “missing CL” the same (`0` vs `-1`).

Owner: `golang/go@e3336a22` `src/net/http/transfer.go`, `src/net/http/request.go` (`reqWriteExcludeHeader`), `src/net/http/h2_bundle.go` (body-open, no `Content-Length`).

Extracts: `.sources/transfer.go.md`, `.sources/request.go.md`, `.sources/h2_bundle.go.md`
