# core_plugin_middleware_sidecar-response

## Purpose

Finish the ModSecurity sidecar HTTP response so the shared WAF client can reuse the TCP connection.

## Requirements

### Requirement: Allow path drains the sidecar body

When the sidecar response status is below 400, the plugin SHALL read the leftover response body up to 256 KiB and discard it before closing that body and calling `next`. The plugin SHALL NOT forward that body to the client. The plugin SHALL NOT expose a configuration key for this limit.

#### Scenario: Sequential allows reuse one connection

- **WHEN** the plugin handles several sequential requests whose sidecar responses are 200 with a whoami-sized body
- **THEN** the mock WAF SHALL see one new TCP connection for those requests

#### Scenario: Allow still calls next without the sidecar body

- **WHEN** the sidecar returns 200 with a non-empty body
- **THEN** the client response SHALL be the `next` handler's response, not the sidecar body

### Requirement: 5xx drains the sidecar body before Close or fail-open

When the sidecar response status is a 5xx, the plugin SHALL read leftover response bytes up to 256 KiB and discard them before closing that body and before fail-open or 502. The plugin SHALL NOT copy that 5xx body to the client.

#### Scenario: Sequential 5xx reuse one connection

- **WHEN** the plugin handles several sequential requests whose sidecar responses are 503 with a whoami-sized body
- **AND** fail-open backoff is not configured
- **THEN** the mock WAF SHALL see one new TCP connection for those requests

### Requirement: Block path still copies the sidecar response

When the sidecar response status is a 4xx, the plugin SHALL copy that response to the client as it does today. Leftover bytes after that copy SHALL still be drained up to 256 KiB. Sidecar 5xx is a WAF failure (`core_plugin_middleware_waf-status`), not a copied block.

#### Scenario: Block still returns the sidecar page

- **WHEN** the sidecar returns 403 with a body
- **THEN** the client SHALL receive status 403 and that body

#### Scenario: Sequential 4xx reuse one connection

- **WHEN** the plugin handles several sequential requests whose sidecar responses are 403 with a whoami-sized body
- **THEN** the mock WAF SHALL see one new TCP connection for those requests
