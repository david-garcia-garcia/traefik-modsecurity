# core_plugin_middleware_body-pool

## Purpose

Keep the request-body reuse pool from retaining buffers larger than `maxBodySizeBytesForPool`, including when the client omits a reliable Content-Length (chunked or unknown size). Keep pooled unread bytes from remaining aliased to a buffer that can be Put and Reset while a sidecar or `next` reader still holds them.

## Requirements

### Requirement: Pool decision uses parsed content length

When the plugin reads a request body and `maxBodySizeBytesForPool` is set, it SHALL choose the reuse pool from `req.ContentLength`, not from the `Content-Length` header string. A non-negative `req.ContentLength` greater than `maxBodySizeBytesForPool` SHALL use an ad-hoc allocation that is not returned to the pool. A `req.ContentLength` of `-1` (unknown size, including chunked transfer) SHALL still use the reuse pool for the read.

#### Scenario: Known length above the pool cap skips the pool

- **WHEN** a POST has `req.ContentLength` greater than `maxBodySizeBytesForPool` and at or under `maxBodySizeBytes`
- **THEN** the plugin SHALL forward that body to the sidecar and to `next`
- **AND** the plugin SHALL NOT return a buffer of that request's size to the body reuse pool

#### Scenario: Unknown length still reads through the pool path

- **WHEN** a POST has `req.ContentLength` of `-1` and a body at or under `maxBodySizeBytes`
- **THEN** the plugin SHALL read the body, forward it to the sidecar, and restore it for `next`

#### Scenario: HTTP/1 chunked body above the pool cap is still forwarded

- **WHEN** a POST is HTTP/1 `Transfer-Encoding: chunked` with a decoded body greater than `maxBodySizeBytesForPool` and at or under `maxBodySizeBytes`
- **THEN** the plugin SHALL forward that body to the sidecar and to `next`
- **AND** the plugin SHALL NOT return a buffer whose capacity exceeds `maxBodySizeBytesForPool`

#### Scenario: Header spoof does not override parsed length

- **WHEN** `req.ContentLength` is greater than `maxBodySizeBytesForPool`
- **AND** the `Content-Length` header is missing or smaller than the pool cap
- **THEN** the plugin SHALL treat the request as above the pool cap (ad-hoc allocation)

### Requirement: Oversized pooled buffers are not retained

After a pooled body read, the plugin SHALL return the buffer to the reuse pool only when that buffer's capacity is at or under `maxBodySizeBytesForPool`. A buffer that grew past that cap SHALL be discarded.

#### Scenario: Grown buffer is not put back

- **WHEN** a pooled read grows the buffer so its capacity exceeds `maxBodySizeBytesForPool`
- **THEN** the plugin SHALL NOT return that buffer to the reuse pool

#### Scenario: Small pooled read is returned

- **WHEN** a pooled read finishes with buffer capacity at or under `maxBodySizeBytesForPool`
- **THEN** the plugin MAY return that buffer to the reuse pool

### Requirement: Body reuse pool is per Plugin core

The reuse pool SHALL belong to the Plugin core created by `New`. Routes that share that core SHALL share that pool. Distinct Plugin cores SHALL NOT share a pool.

#### Scenario: Distinct cores do not share a pool

- **WHEN** two Plugin cores are constructed
- **THEN** each core SHALL have its own body reuse pool

### Requirement: Concurrent mixed-size body reads on one core do not race

When one Plugin core handles concurrent `ServeHTTP` calls whose inbound bodies mix pooled (at or under `maxBodySizeBytesForPool`) and ad-hoc (above that cap, at or under `maxBodySizeBytes`) sizes, each request SHALL still forward its own body to the sidecar and to `next`. The core SHALL NOT corrupt those bodies. The Go race detector SHALL report no race on that path.

#### Scenario: Mixed pooled and ad-hoc bodies in parallel

- **WHEN** one Plugin core serves concurrent POSTs, some with body size at or under `maxBodySizeBytesForPool` and some with body size above that cap and at or under `maxBodySizeBytes`
- **THEN** each sidecar call and each `next` call SHALL receive that request's own body
- **AND** `go test -race` SHALL report no data race on that path

### Requirement: Pooled body bytes are not aliased after Put

After a pooled inbound-body read, the plugin SHALL copy the unread bytes into a slice the pool does not own before building the sidecar request body or restoring `req.Body` for `next`. The plugin SHALL NOT Put a `bytes.Buffer` while any sidecar RoundTripper or `next` reader still aliases that buffer's backing array. A later Get and Reset of the same buffer SHALL NOT change what the earlier request's sidecar or `next` readers observe.

#### Scenario: Delayed sidecar body read still sees the first POST

- **WHEN** a pooled POST body is all byte `0xAA` and the sidecar RoundTripper returns 403 without reading `Request.Body` until after `ServeHTTP` has returned
- **AND** a second pooled POST on the same Plugin core then copies a body of all byte `0xBB` (so the pool can reuse the first buffer)
- **THEN** when the first RoundTripper reads `Request.Body`, that body SHALL be the first POST (`0xAA`), not the second (`0xBB`)
- **AND** the first request SHALL still be a security block (sidecar 403 copied to the client)

#### Scenario: Copy-out still forwards a small pooled body on allow

- **WHEN** a pooled POST is allowed by the sidecar (status below 300)
- **THEN** the sidecar and `next` SHALL each receive that request's own body
