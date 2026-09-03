---
url: https://github.com/golang/go/blob/e3336a22ad3f0a90bd252c95d8b5544e02674205/src/net/http/transfer.go
title: net/http transfer.go readTransfer / fixLength
fetched: 2026-09-01
authority: source
ref: golang/go@e3336a22ad3f0a90bd252c95d8b5544e02674205:src/net/http/transfer.go
---

readTransfer comment: Transfer-Encoding: chunked, and overriding Content-Length.

parseTransferEncoding: if Transfer-Encoding is present, delete(t.Header, "Transfer-Encoding"). HTTP/1.0: ignore TE. HTTP/1.1: only a single field equal-fold "chunked"; otherwise unsupportedTEError. Sets t.Chunked = true.

fixLength (RFC 7230 §3.3 / RFC 9112 quote in comments):

- Multiple Content-Length values that differ after trim: error "message cannot contain multiple Content-Length headers".
- Identical duplicates: Del then Add the first trimmed value.
- Any remaining Content-Length is parseContentLength'd; invalid (empty unless GODEBUG=httplaxcontentlength=1, non-numeric, overflow) returns error even when chunked.
- if chunked: header.Del("Content-Length"); return -1, nil. Comment: chunked requests with valid or missing Content-Length are accepted after removing Content-Length.
- else if Content-Length present: return parsed n.
- else: header.Del("Content-Length"); for a request return 0 (default no body); for a response return -1.

parseContentLength: no headers → -1; empty string → error (or -1 with httplaxcontentlength=1); strconv.ParseUint base 10, 63 bits.

Outgoing: shouldSendContentLength is false when TransferEncoding is chunked. writeHeader writes Content-Length from t.ContentLength or Transfer-Encoding: chunked, not from Header. Header keys Transfer-Encoding, Trailer, Content-Length are skipped when copying remaining headers.

outgoingLength (request.go, called from newTransferWriter): Body nil/NoBody → 0; ContentLength != 0 → that value; else -1 (0 + non-nil Body is unknown).
