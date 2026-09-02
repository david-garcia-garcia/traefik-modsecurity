## Purpose

Puts the original request Host and the immediate peer IP on the ModSecurity sidecar request so host-sensitive rules and the audit log see the client, not the sidecar URL.

## ADDED Requirements

### Requirement: Sidecar request Host is the original Host

When the plugin builds the request it sends to ModSecurity, that request SHALL use the incoming request Host. The plugin SHALL NOT leave the sidecar URL host as the Host the WAF evaluates. The plugin SHALL NOT add a public configuration key for this.

#### Scenario: Original Host reaches the sidecar

- **WHEN** an inspected request has Host `app.example.com` and the sidecar URL host is different
- **THEN** the sidecar SHALL receive Host `app.example.com`

### Requirement: Sidecar request appends the peer to X-Forwarded-For

When the plugin builds the request it sends to ModSecurity, it SHALL take the IP from the incoming RemoteAddr (host part of `host:port`) and append it to `X-Forwarded-For`. If the incoming request already has one or more `X-Forwarded-For` values, the plugin SHALL join those values with `, ` and append `, ` plus the peer IP. If RemoteAddr has no `host:port` form, the plugin SHALL leave any existing `X-Forwarded-For` unchanged and SHALL NOT invent an IP. The plugin SHALL NOT set `X-Real-IP`, `X-Forwarded-Host`, or `X-Forwarded-Proto`.

#### Scenario: Peer IP is set when no chain exists

- **WHEN** an inspected request has RemoteAddr `203.0.113.9:54321` and no `X-Forwarded-For`
- **THEN** the sidecar SHALL receive `X-Forwarded-For` `203.0.113.9`

#### Scenario: Peer IP is appended to an existing chain

- **WHEN** an inspected request has RemoteAddr `203.0.113.9:54321` and `X-Forwarded-For` `198.51.100.1`
- **THEN** the sidecar SHALL receive `X-Forwarded-For` `198.51.100.1, 203.0.113.9`

#### Scenario: IPv6 peer is the host part only

- **WHEN** an inspected request has RemoteAddr `[2001:db8::1]:443`
- **THEN** the sidecar SHALL receive `X-Forwarded-For` containing `2001:db8::1` and SHALL NOT include the port

#### Scenario: Unparseable RemoteAddr does not invent an IP

- **WHEN** an inspected request has RemoteAddr `not-a-host-port` and `X-Forwarded-For` `198.51.100.1`
- **THEN** the sidecar SHALL receive `X-Forwarded-For` `198.51.100.1`
