## MODIFIED Requirements

### Requirement: Allow path drains the sidecar body

When the sidecar response status is below 300, the plugin SHALL read the leftover response body up to 256 KiB and discard it before closing that body and calling `next`. The plugin SHALL NOT forward that body to the client. The plugin SHALL NOT expose a configuration key for this limit. The plugin SHALL NOT return HTTP 405 on that allow path.

#### Scenario: Sequential allows reuse one connection

- **WHEN** the plugin handles several sequential requests whose sidecar responses are 200 with a whoami-sized body
- **THEN** the mock WAF SHALL see one new TCP connection for those requests

#### Scenario: Allow still calls next without the sidecar body

- **WHEN** the sidecar returns 200 with a non-empty body
- **THEN** the client response SHALL be the `next` handler's response, not the sidecar body

#### Scenario: Allow on Authelia login POST is not 405

- **WHEN** the plugin inspects `POST /api/firstfactor` and the sidecar returns 200
- **THEN** the client SHALL receive the `next` handler's response
- **AND** the client status SHALL NOT be 405

### Requirement: Block path still copies the sidecar response

When the sidecar response status is a 3xx or a 4xx, the plugin SHALL copy that response to the client and SHALL NOT call `next`. Leftover bytes after that copy SHALL still be drained up to 256 KiB. Sidecar 5xx is a WAF failure (`core_plugin_middleware_waf-status`), not a copied block.

#### Scenario: Block still returns the sidecar page

- **WHEN** the sidecar returns 403 with a body
- **THEN** the client SHALL receive status 403 and that body

#### Scenario: Redirect status is a block

- **WHEN** the sidecar returns 302 with a Location header and a body
- **THEN** the client SHALL receive status 302, that Location, and that body
- **AND** `next` SHALL NOT be called

#### Scenario: Sequential 4xx reuse one connection

- **WHEN** the plugin handles several sequential requests whose sidecar responses are 403 with a whoami-sized body
- **THEN** the mock WAF SHALL see one new TCP connection for those requests

#### Scenario: Sidecar 405 on Authelia login POST is copied

- **WHEN** the plugin inspects `POST /api/firstfactor` and the sidecar returns 405 with a body
- **THEN** the client SHALL receive status 405 and that body
- **AND** `next` SHALL NOT be called
