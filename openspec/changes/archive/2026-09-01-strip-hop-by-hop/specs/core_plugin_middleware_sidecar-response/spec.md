## MODIFIED Requirements

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
