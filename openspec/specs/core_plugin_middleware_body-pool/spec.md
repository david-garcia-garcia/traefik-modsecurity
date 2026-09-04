# core_plugin_middleware_body-pool

## Purpose

Keep the request-body reuse pool from retaining oversized checkout buffers, including when the client omits a reliable Content-Length (chunked or unknown size). Keep pooled unread bytes from remaining aliased to a buffer that can be Put and Reset while a sidecar or `next` reader still holds them — by copying pooled bytes out before Put (required under Yaegi local plugins; a `doneReadCloser` gate hung client response flush in Traefik Yaegi).

## Requirements

### Requirement: Pool decision uses parsed content length

When the plugin reads a request body and `maxBodySizeBytesForPool` is set, it SHALL choose the reuse pool from `req.ContentLength`, not from the `Content-Length` header string. A non-negative `req.ContentLength` greater than `maxBodySizeBytesForPool` SHALL use an ad-hoc allocation that is not returned to the pool. A `req.ContentLength` of `-1` (unknown size, including chunked transfer) SHALL still enter the reuse-pool read path, bounded so a body larger than the pool cap does not grow a checkout buffer past that path's Put rules.

#### Scenario: Known length above the pool cap skips the pool

- **WHEN** a POST has `req.ContentLength` greater than `maxBodySizeBytesForPool` and at or under `maxBodySizeBytes`
- **THEN** the plugin SHALL forward that body to the sidecar and to `next`
- **AND** the plugin SHALL NOT return a buffer of that request's size to the body reuse pool

#### Scenario: Unknown length still reads through the pool path

- **WHEN** a POST has `req.ContentLength` of `-1` and a body at or under `maxBodySizeBytesForPool`
- **THEN** the plugin SHALL read the body through the pool, forward it to the sidecar, and restore it for `next`
- **AND** after both body consumers finish, the plugin SHALL return that checkout buffer to the pool

#### Scenario: HTTP/1 chunked body above the pool cap is still forwarded

- **WHEN** a POST is HTTP/1 `Transfer-Encoding: chunked` with a decoded body greater than `maxBodySizeBytesForPool` and at or under `maxBodySizeBytes`
- **THEN** the plugin SHALL forward that body to the sidecar and to `next`
- **AND** the plugin SHALL Put the bounded pool checkout buffer used for the peek (not retain an unbounded grown buffer)
- **AND** the forwarded body SHALL be an owned slice (not an alias of a pooled buffer)

#### Scenario: Header spoof does not override parsed length

- **WHEN** `req.ContentLength` is greater than `maxBodySizeBytesForPool`
- **AND** the `Content-Length` header is missing or smaller than the pool cap
- **THEN** the plugin SHALL treat the request as above the pool cap (ad-hoc allocation)

### Requirement: Unknown-length reads stay within the pool checkout bound

On the pool path, the plugin SHALL NOT `io.Copy` the entire unknown-length body into the checkout buffer. It SHALL read at most `maxBodySizeBytesForPool` into the checkout buffer. If more body bytes remain, it SHALL Put that checkout buffer and assemble an owned slice for the full body. If the body fits in the bound, the plugin SHALL copy those bytes into an owned slice and Put the checkout buffer before returning (so sidecar and `next` never alias a pooled buffer).

#### Scenario: Chunked overflow Puts the checkout buffer

- **WHEN** a pooled read with `req.ContentLength` of `-1` finds more than `maxBodySizeBytesForPool` body bytes
- **THEN** the plugin SHALL return the checkout buffer to the reuse pool before serving the request
- **AND** sidecar and `next` SHALL each receive the full owned body

#### Scenario: Bounded pooled read Puts before return

- **WHEN** a pooled read finishes with a body at or under `maxBodySizeBytesForPool`
- **THEN** the plugin SHALL copy those bytes into an owned slice and Put the checkout buffer before `ServeHTTP` continues to the sidecar
- **AND** sidecar and `next` SHALL each receive that owned slice (not an alias of a pooled buffer)

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

### Requirement: Pooled body is copied out before Put

After a successful pooled inbound-body read, the plugin SHALL copy the bytes into an owned slice and Put the checkout buffer before returning from the read. Sidecar and `next` SHALL NOT receive a slice that aliases a pooled `bytes.Buffer` backing array. A later Get and Reset of the same buffer SHALL NOT change what an earlier request's readers observe.

An empty pooled body SHALL Put immediately.

#### Scenario: Delayed sidecar body read still sees the first POST

- **WHEN** a pooled POST body is all byte `0xAA` and the sidecar RoundTripper holds `Request.Body` without Closing until after a second pooled POST on the same Plugin core has begun
- **THEN** when the first RoundTripper reads `Request.Body`, that body SHALL be the first POST (`0xAA`), not the second (`0xBB`)
- **AND** the first checkout buffer SHALL already have been Put (with a copy retained for the first RoundTrip)

#### Scenario: Allow path does not need consumer Close to Put

- **WHEN** a pooled POST is allowed by the sidecar (status below 300)
- **AND** a custom RoundTripper does not Close the sidecar request body
- **AND** `next` does not Close `req.Body`
- **THEN** the checkout buffer SHALL already have been Put during the inbound body read (owned copies remain for both consumers)

#### Scenario: Pooled allow still forwards the body

- **WHEN** a pooled POST is allowed by the sidecar (status below 300)
- **THEN** the sidecar and `next` SHALL each receive that request's own body
