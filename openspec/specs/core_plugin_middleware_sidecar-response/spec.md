# core_plugin_middleware_sidecar-response

## Purpose

Finish the ModSecurity sidecar HTTP response: drain the allow-path body so the shared WAF client can reuse the TCP connection, and copy a filtered block-path response to the client.

## Requirements

### Requirement: Allow path drains the sidecar body

When the sidecar response status is below 400, the plugin SHALL read the leftover response body up to 256 KiB and discard it before closing that body and calling `next`. The plugin SHALL NOT forward that body to the client. The plugin SHALL NOT expose a configuration key for this limit.

#### Scenario: Sequential allows reuse one connection

- **WHEN** the plugin handles several sequential requests whose sidecar responses are 200 with a whoami-sized body
- **THEN** the mock WAF SHALL see one new TCP connection for those requests

#### Scenario: Allow still calls next without the sidecar body

- **WHEN** the sidecar returns 200 with a non-empty body
- **THEN** the client response SHALL be the `next` handler's response, not the sidecar body

### Requirement: Block path still copies the sidecar response

When the sidecar response status is 400 or higher, the plugin SHALL copy that status and body to the client. The plugin SHALL NOT forward hop-by-hop headers (`Connection`, `Keep-Alive`, `Transfer-Encoding`, `Upgrade`, any header whose name starts with `Proxy-`, `Te`, `Trailer`, and any header named by a token in the sidecar `Connection` field) or `Server`. The plugin SHALL NOT expose a configuration key for this filter. This drain does not change the block-path status or body.

#### Scenario: Block still returns the sidecar page

- **WHEN** the sidecar returns 403 with a body
- **THEN** the client SHALL receive status 403 and that body

#### Scenario: Block drops hop-by-hop and Server headers

- **WHEN** the sidecar returns 403 with `Connection: close`, `Server: Apache`, and `Content-Type: text/html`
- **THEN** the client response SHALL include `Content-Type: text/html`
- **AND** the client response SHALL NOT include `Connection` or `Server`

#### Scenario: Block drops Proxy- prefix and Connection-listed names

- **WHEN** the sidecar returns 403 with `Proxy-Authenticate: Basic`, `X-Sidecar-Hop: 1`, and `Connection: close, X-Sidecar-Hop`
- **THEN** the client response SHALL NOT include `Proxy-Authenticate` or `X-Sidecar-Hop`
