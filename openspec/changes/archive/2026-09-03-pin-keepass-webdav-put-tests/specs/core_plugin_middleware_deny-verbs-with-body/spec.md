## ADDED Requirements

### Requirement: Default list does not deny PUT; KeePass-sized PUT is inspected

CreateConfig SHALL NOT include PUT in the default `denyVerbsWithBody` list. When a PUT request carries a 228565-byte body (the Content-Length from acouvreur/traefik-modsecurity-plugin#14) and `denyVerbsWithBody` is the CreateConfig default, the plugin SHALL send that body to ModSecurity. The plugin SHALL NOT return HTTP 400 for “method must not have a body.” That body size SHALL be under the CreateConfig `maxBodySizeBytes` default (8 MiB), so the plugin SHALL NOT return a local HTTP 413 for this request.

#### Scenario: Default PUT is not a denied-verb body

- **WHEN** `denyVerbsWithBody` is the CreateConfig default
- **THEN** PUT SHALL NOT be on that list

#### Scenario: 228565-byte WebDAV PUT is forwarded to the sidecar

- **WHEN** a PUT to a WebDAV `.kdbx.tmp` path carries a 228565-byte body
- **AND** `denyVerbsWithBody` and `maxBodySizeBytes` are the CreateConfig defaults
- **AND** the sidecar allows the request
- **THEN** ModSecurity SHALL receive PUT and that body
- **AND** `next` SHALL receive that same body
- **AND** the client SHALL NOT receive a local 400 or local 413 from the plugin
