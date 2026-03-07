## MODIFIED Requirements

### Requirement: WAF forwarding URL construction
The system SHALL construct the ModSecurity forwarding URL by concatenating `modSecurityUrl` with the origin-form of the incoming request URI (path and query string), regardless of whether the original request used origin-form or absolute-form RequestURI.

#### Scenario: Origin-form RequestURI is forwarded correctly
- **WHEN** an HTTP/1.1 request arrives with a path-only RequestURI (e.g. `/api/resource?foo=bar`)
- **THEN** the plugin forwards the request to `<modSecurityUrl>/api/resource?foo=bar`

#### Scenario: Absolute-form RequestURI is normalised before forwarding
- **WHEN** an HTTP/1.0 or proxy-style request arrives with an absolute-form RequestURI (e.g. `http://example.com/api/resource?foo=bar`)
- **THEN** the plugin forwards the request to `<modSecurityUrl>/api/resource?foo=bar`
- **AND** the scheme and host from the original RequestURI are NOT included in the forwarded URL
