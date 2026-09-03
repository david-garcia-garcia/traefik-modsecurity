## ADDED Requirements

### Requirement: Concurrent mixed-size body reads on one core do not race

When one Plugin core handles concurrent `ServeHTTP` calls whose inbound bodies mix pooled (at or under `maxBodySizeBytesForPool`) and ad-hoc (above that cap, at or under `maxBodySizeBytes`) sizes, each request SHALL still forward its own body to the sidecar and to `next`. The core SHALL NOT corrupt those bodies. The Go race detector SHALL report no race on that path.

#### Scenario: Mixed pooled and ad-hoc bodies in parallel

- **WHEN** one Plugin core serves concurrent POSTs, some with body size at or under `maxBodySizeBytesForPool` and some with body size above that cap and at or under `maxBodySizeBytes`
- **THEN** each sidecar call and each `next` call SHALL receive that request's own body
- **AND** `go test -race` SHALL report no data race on that path
