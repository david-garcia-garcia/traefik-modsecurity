# core_plugin_middleware_body-pool

## Purpose

Keep the request-body reuse pool from retaining buffers larger than `maxBodySizeBytesForPool`, including when the client omits a reliable Content-Length (chunked or unknown size).

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
