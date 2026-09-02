# core_plugin_middleware_health-failures

## Purpose

Say which ModSecurity sidecar call errors count as WAF health failures so a client disconnect cannot trip fail-open, while a slow or down sidecar still can.

## Requirements

### Requirement: Inbound context done is not a WAF health failure

When a health tracker is configured and the sidecar call returns an error because the inbound request context is already done (canceled or deadline exceeded), the plugin SHALL NOT record that error as a WAF health failure. The plugin SHALL NOT mark the WAF unhealthy from that error alone.

#### Scenario: Inbound cancel does not trip the health tracker

- **WHEN** the inbound request context is canceled while the sidecar has not yet responded
- **AND** a health tracker is configured with failure threshold 1
- **THEN** the plugin SHALL NOT mark the WAF unhealthy

#### Scenario: Inbound deadline does not trip the health tracker

- **WHEN** the inbound request context deadline fires while the sidecar has not yet responded
- **AND** a health tracker is configured with failure threshold 1
- **THEN** the plugin SHALL NOT mark the WAF unhealthy

### Requirement: Client timeout and sidecar errors remain health failures

When a health tracker is configured and the sidecar call fails while the inbound request context is still live, the plugin SHALL record that error as a WAF health failure. That includes the configured client timeout (`timeoutMillis`) and other sidecar or transport errors.

#### Scenario: Client timeout still trips the health tracker

- **WHEN** the inbound request context stays live
- **AND** the sidecar does not respond before the configured client timeout
- **AND** a health tracker is configured with failure threshold 1
- **THEN** the plugin SHALL mark the WAF unhealthy

#### Scenario: Unreachable sidecar still trips the health tracker

- **WHEN** the inbound request context stays live
- **AND** the sidecar call fails because the sidecar cannot be reached
- **AND** a health tracker is configured with failure threshold 1
- **THEN** the plugin SHALL mark the WAF unhealthy
