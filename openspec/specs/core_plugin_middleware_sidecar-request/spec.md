# core_plugin_middleware_sidecar-request

## Purpose

Puts the original request Host on the ModSecurity sidecar request and forwards Traefik’s post-wrapper identity headers as-is so host-sensitive rules see the client Host and CRS can rewrite `REMOTE_ADDR` from `X-Real-IP` when the sidecar trusts Traefik.

## Decision

The plugin does not derive client IP from `req.RemoteAddr`. It copies Traefik’s post-wrapper headers and sets Host. CRS must trust Traefik via `X-Real-IP` (Apache `REMOTEIP_HEADER=X-Real-IP` + `REMOTEIP_INT_PROXY`; nginx `real_ip_header X-Real-IP` + `set_real_ip_from`).

Why: Traefik already decided the real client. Appending `RemoteAddr` invents a hop Traefik deliberately did not put on `X-Forwarded-For`; behind a trusted load balancer that hop is the load balancer.

Operators who set `forwardedHeaders.trustedIPs` and want the leftover XFF chain as `REMOTE_ADDR` set `REMOTEIP_HEADER=X-Forwarded-For` (or nginx `real_ip_header X-Forwarded-For`) themselves.

## Requirements

### Requirement: Sidecar request Host is the original Host

When the plugin builds the request it sends to ModSecurity, that request SHALL use the incoming request Host. The plugin SHALL NOT leave the sidecar URL host as the Host the WAF evaluates. The plugin SHALL NOT add a public configuration key for this.

#### Scenario: Original Host reaches the sidecar

- **WHEN** an inspected request has Host `app.example.com` and the sidecar URL host is different
- **THEN** the sidecar SHALL receive Host `app.example.com`

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

### Requirement: Trusted CRS sidecar records the Traefik client on deny

When a shipped compose reference trusts Traefik via `X-Real-IP` (Apache: `REMOTEIP_HEADER=X-Real-IP` and `REMOTEIP_INT_PROXY` covering the Traefik hop; nginx: `REAL_IP_HEADER=X-Real-IP` and `SET_REAL_IP_FROM` covering the Traefik hop), a request that CRS denies SHALL appear in the WAF audit log with a client IP equal to the address Traefik logged as the request's client host. This requirement applies to both the shipped Apache compose references and the nginx test compose reference. The plugin SHALL NOT set `X-Real-IP`.

#### Scenario: Deny audit log has Traefik ClientHost

- **WHEN** an inspected request is denied by CRS and the compose WAF trusts Traefik via `X-Real-IP`
- **THEN** the WAF JSON audit record for that request SHALL have the client IP field (`transaction.remote_address` or the nginx-equivalent) equal to Traefik access-log `ClientHost` for the same request
