## MODIFIED Requirements

### Requirement: Inbound cancel is not a WAF health failure

When backoff is enabled and the sidecar call returns an error because the inbound request context is canceled, the plugin SHALL NOT count that error as a WAF health failure. The plugin SHALL NOT skip later sidecar calls from that error alone. A client can close the connection; that is not a WAF outage. If the call was already admitted, the plugin SHALL NOT record an outcome for it.

#### Scenario: Inbound cancel does not trip the health tracker

- **WHEN** the inbound request context is canceled while the sidecar has not yet responded
- **AND** backoff is enabled with failure threshold 1
- **THEN** the plugin SHALL NOT skip the sidecar on later requests due to unhealthy state

### Requirement: Client timeout, inbound deadline, and sidecar errors remain health failures

When backoff is enabled and the sidecar call fails while the inbound request is not canceled, the plugin SHALL count that error as a WAF health failure. That includes the configured client timeout (`timeoutMillis`), an inbound request deadline that fires while waiting on the sidecar, and other sidecar or transport errors.

#### Scenario: Inbound deadline trips the health tracker

- **WHEN** the inbound request context deadline fires while the sidecar has not yet responded
- **AND** backoff is enabled with failure threshold 1
- **THEN** the plugin SHALL skip the sidecar on later requests until cooldown ends

#### Scenario: Client timeout still trips the health tracker

- **WHEN** the inbound request context stays live
- **AND** the sidecar does not respond before the configured client timeout
- **AND** backoff is enabled with failure threshold 1
- **THEN** the plugin SHALL skip the sidecar on later requests until cooldown ends

#### Scenario: Unreachable sidecar still trips the health tracker

- **WHEN** the inbound request context stays live
- **AND** the sidecar call fails because the sidecar cannot be reached
- **AND** backoff is enabled with failure threshold 1
- **THEN** the plugin SHALL skip the sidecar on later requests until cooldown ends
