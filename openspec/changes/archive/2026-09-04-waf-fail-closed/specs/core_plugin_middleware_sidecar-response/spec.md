## MODIFIED Requirements

### Requirement: 5xx drains the sidecar body before Close or WAF-failure handling

When the sidecar response status is a 5xx, the plugin SHALL read leftover response bytes up to 256 KiB and discard them before closing that body and before fail-open to next or fail-close HTTP 502. The plugin SHALL NOT copy that 5xx body to the client.

#### Scenario: Sequential 5xx reuse one connection

- **WHEN** the plugin handles several sequential requests whose sidecar responses are 503 with a whoami-sized body
- **AND** fail-open backoff is not configured
- **THEN** the mock WAF SHALL see one new TCP connection for those requests
