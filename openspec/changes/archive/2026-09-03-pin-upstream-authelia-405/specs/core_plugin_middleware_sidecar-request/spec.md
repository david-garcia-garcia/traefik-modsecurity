## MODIFIED Requirements

### Requirement: Sidecar request Host is the original Host

When the plugin builds the request it sends to ModSecurity, that request SHALL use the incoming request Host. The plugin SHALL NOT leave the sidecar URL host as the Host the WAF evaluates. The plugin SHALL NOT add a public configuration key for this.

#### Scenario: Original Host reaches the sidecar

- **WHEN** an inspected request has Host `app.example.com` and the sidecar URL host is different
- **THEN** the sidecar SHALL receive Host `app.example.com`

#### Scenario: Deny audit log has original Host

- **WHEN** an inspected request with Host `app.example.test` is denied by CRS
- **THEN** the WAF JSON audit record for that request SHALL have Host `app.example.test` (`request.headers.Host` on Apache CRS 4.3, `transaction.request.headers.Host` on nginx CRS 4.3)
- **AND** that Host SHALL NOT be the sidecar URL host (`waf`, `waf:8080`)

#### Scenario: Authelia login POST Host is the portal Host

- **WHEN** the plugin inspects `POST /api/firstfactor` with Host `auth.example.com`
- **THEN** the sidecar SHALL receive Host `auth.example.com`
- **AND** that Host SHALL NOT be the sidecar URL host

### Requirement: Sidecar request does not invent an X-Forwarded-For hop

When the plugin builds the request it sends to ModSecurity, it SHALL copy incoming headers as-is and SHALL set Host. The plugin SHALL NOT append `req.RemoteAddr` to `X-Forwarded-For`. The plugin SHALL NOT set `X-Real-IP`, `X-Forwarded-Host`, or `X-Forwarded-Proto`. If the incoming request already has `X-Real-Ip` or `X-Forwarded-For`, those values SHALL reach the sidecar unchanged.

#### Scenario: RemoteAddr does not become an XFF hop

- **WHEN** an inspected request has RemoteAddr `203.0.113.9:54321` and no `X-Forwarded-For`
- **THEN** the sidecar SHALL NOT receive `X-Forwarded-For` `203.0.113.9`

#### Scenario: Incoming X-Forwarded-For is copied without appending RemoteAddr

- **WHEN** an inspected request has RemoteAddr `203.0.113.9:54321` and `X-Forwarded-For` `198.51.100.1`
- **THEN** the sidecar SHALL receive `X-Forwarded-For` `198.51.100.1`

#### Scenario: Incoming X-Real-Ip is copied

- **WHEN** an inspected request has `X-Real-Ip` `198.51.100.10`
- **THEN** the sidecar SHALL receive `X-Real-Ip` `198.51.100.10`

#### Scenario: Authelia login POST copies leftover identity headers

- **WHEN** the plugin inspects `POST /api/firstfactor` with RemoteAddr `203.0.113.9:54321`, `X-Forwarded-For` `198.51.100.1`, and `X-Real-Ip` `198.51.100.10`
- **THEN** the sidecar SHALL receive `X-Forwarded-For` `198.51.100.1` and `X-Real-Ip` `198.51.100.10`
- **AND** the sidecar SHALL NOT receive `X-Forwarded-For` with `203.0.113.9` appended
