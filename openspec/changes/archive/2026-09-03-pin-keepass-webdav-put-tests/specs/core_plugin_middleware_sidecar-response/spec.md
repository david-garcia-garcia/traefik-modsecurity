## ADDED Requirements

### Requirement: Sidecar 400 and 413 on a KeePass-sized PUT are copied as a block

When a PUT request carries a 228565-byte body and the sidecar returns HTTP 400 or HTTP 413, the plugin SHALL copy that status to the client and SHALL NOT call `next`. The plugin SHALL NOT replace that sidecar status with a local deny-verb 400 or a local oversize 413. The plugin SHALL NOT expose a configuration key that shadows sidecar `SecRequestBodyNoFilesLimit`.

#### Scenario: Sidecar 400 on the reporter PUT is copied

- **WHEN** a PUT carries a 228565-byte body
- **AND** the sidecar returns HTTP 400
- **THEN** the client SHALL receive HTTP 400
- **AND** `next` SHALL NOT be called

#### Scenario: Sidecar 413 on the reporter PUT is copied

- **WHEN** a PUT carries a 228565-byte body
- **AND** the sidecar returns HTTP 413
- **THEN** the client SHALL receive HTTP 413
- **AND** `next` SHALL NOT be called
