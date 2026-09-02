# 🛡️ Traefik ModSecurity Plugin

[![Build Status](https://github.com/david-garcia-garcia/traefik-modsecurity/actions/workflows/build.yml/badge.svg)](https://github.com/david-garcia-garcia/traefik-modsecurity/actions/workflows/build.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/david-garcia-garcia/traefik-modsecurity)](https://goreportcard.com/report/github.com/david-garcia-garcia/traefik-modsecurity)
[![Go Version](https://img.shields.io/github/go-mod/go-version/david-garcia-garcia/traefik-modsecurity)](https://img.shields.io/github/go-mod/go-version/david-garcia-garcia/traefik-modsecurity)
[![Latest Release](https://img.shields.io/github/v/release/david-garcia-garcia/traefik-modsecurity?sort=semver)](https://github.com/david-garcia-garcia/traefik-modsecurity/releases/latest)
[![License](https://img.shields.io/badge/license-Apache%202.0-brightgreen.svg)](LICENSE)

A Traefik plugin that integrates with [OWASP ModSecurity Core Rule Set (CRS)](https://github.com/coreruleset/coreruleset) to provide Web Application Firewall (WAF) protection for your applications.

> [!TIP]
> 
> **Traefik Security**
> 
> The basic middlewares you need to secure your Traefik ingress:
> 
> 🌍 **Geoblock**: [david-garcia-garcia/traefik-geoblock](https://github.com/david-garcia-garcia/traefik-geoblock) - Block or allow requests based on IP geolocation  
> 🛡️ **CrowdSec**: [maxlerebourg/crowdsec-bouncer-traefik-plugin](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin) - Real-time threat intelligence and automated blocking  
> 🔒 **ModSecurity CRS**: [david-garcia-garcia/traefik-modsecurity](https://github.com/david-garcia-garcia/traefik-modsecurity) - Web Application Firewall with OWASP Core Rule Set  
> 🚦 **Ratelimit**: [Traefik Rate Limit](https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/ratelimit/) - Control request rates and prevent abuse

> [!WARNING]
>
> **You should not run middlewares as Yaegi plugins in production.**
>
> Traefik's default plugin system runs plugins via [Yaegi](https://github.com/traefik/yaegi) (a Go interpreter) at runtime. Middlewares run on every request, so they sit on the hot path. Using an interpreter for that workload has concrete drawbacks related to memory management, CPU usage and observability (see [feat: improve pprof experience by adding wrappers to interpreted functions by david-garcia-garcia · Pull Request #1712 · traefik/yaegi](https://github.com/traefik/yaegi/pull/1712))
>
> For production deployments where middlewares handle substantial traffic, use a Traefik build that **compiles those middlewares into the binary** instead of loading them as Yaegi plugins such as in [david-garcia-garcia/traefik-with-plugins: Traefik container with preloaded plugins in it](https://github.com/david-garcia-garcia/traefik-with-plugins)
>
> **For more details and discussion, read [Traefik issue #12213](https://github.com/traefik/traefik/issues/12213) in the Traefik issue queue.**

[Traefik ModSecurity Plugin](#-traefik-modsecurity-plugin)

- [Demo](#demo)
- [Usage (docker-compose.yml)](#usage-docker-composeyml)
- [How it works](#how-it-works)
- [Trust this middleware (client IP in WAF logs)](#trust-this-middleware-client-ip-in-waf-logs)
- [Testing](#-testing)
- [Configuration](#️-configuration)
- [Local development](#local-development-docker-composelocalyml)

## Demo

Demo with WAF intercepting relative access in query param.

![Demo](./img/waf.gif)

## Usage (docker-compose.yml)

See [docker-compose.yml](docker-compose.yml)

1. docker-compose up
2. Go to http://localhost/website, the request is received without warnings
3. Go to http://localhost/website?test=../etc, the request is intercepted and returned with 403 Forbidden by
   owasp/modsecurity
4. You can you bypass the WAF and check attacks at http://localhost/bypass?test=../etc

## How it works

This is a very simple plugin that proxies the query to the owasp/modsecurity apache container.

The plugin classifies the sidecar HTTP status:

- **2xx / 3xx** — allow: forward the request to the real service.
- **4xx** — security block: copy the sidecar response (the WAF error page) to the client.
- **5xx** — WAF failure, not a block: set `modSecurityStatusRequestHeader` to `error` when configured, count a health-tracker failure, then fail-open or return 502. The sidecar 5xx body is not forwarded.

The *dummy* service is created so the waf container forward the request to a service and respond with 200 OK all the
time.

## Trust this middleware (client IP in WAF logs)

Copying headers is not enough for ModSecurity to treat the visitor as the client. `REMOTE_ADDR` (audit logs, error logs, IP collections, and any IPS that parses those logs) stays the **Traefik-to-sidecar TCP hop** until CRS is told to trust Traefik.

What this plugin sends to `modSecurityUrl`:

- Sets the sidecar request `Host` to the incoming `Host`.
- Copies Traefik’s headers as-is, including `X-Real-Ip` when Traefik already set it, and leftover `X-Forwarded-For` only if Traefik left one.
- Does **not** append `RemoteAddr` to `X-Forwarded-For`.
- Does **not** set `X-Real-IP`.

Traefik’s entrypoint `forwardedheaders` is the source of truth (`X-Real-Ip`; leftover XFF only if the peer is trusted). CRS / ModSecurity does **not** read those headers as `REMOTE_ADDR` on its own.

### Apache CRS (demo compose)

Use [docker-compose.yml](docker-compose.yml) as the reference. The `waf` service sets:

```yaml
REMOTEIP_HEADER: X-Real-IP
REMOTEIP_INT_PROXY: 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16
```

`REMOTEIP_INT_PROXY` must include the network Traefik uses to reach the sidecar (Docker bridge is usually `172.16.0.0/12`). The image default `10.1.0.0/16` does not. Do **not** set `0.0.0.0/0`.

The shipped `4.3.0-apache-alpine-202406090906` pin hardcodes `RemoteIPHeader X-Forwarded-For`, so `REMOTEIP_HEADER` alone does nothing. Compose also mounts [crs-apache/httpd-vhosts.conf](crs-apache/httpd-vhosts.conf) to set `RemoteIPHeader X-Real-IP`.

### nginx CRS (test compose is the reference)

Use [docker-compose.test.nginx.yml](docker-compose.test.nginx.yml). The official image maps:

```yaml
REAL_IP_HEADER: X-Real-IP
SET_REAL_IP_FROM: 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
REAL_IP_RECURSIVE: on
```

Those become `real_ip_header X-Real-IP` and `set_real_ip_from` for the Traefik net. `SET_REAL_IP_FROM` is comma-separated. Do **not** set `0.0.0.0/0`.

The shipped `4.3.0-nginx-alpine-202406090906` pin applies those env vars only inside `location /`, which is too late for ModSecurity. Compose also mounts [crs-nginx/realip.conf](crs-nginx/realip.conf) at http level. The nginx user cannot write `/var/log`; the test compose sets `MODSEC_AUDIT_LOG=/tmp/modsecurity/modsec_audit.log`.

Operators who set Traefik `forwardedHeaders.trustedIPs` and want leftover XFF as `REMOTE_ADDR` configure that on CRS themselves (`REMOTEIP_HEADER=X-Forwarded-For` or `REAL_IP_HEADER=X-Forwarded-For`).

Without this, every deny is attributed to the Traefik container IP. An IPS that blocks from the WAF log then bans Traefik, not the attacker.

## Testing

### Integration Tests

Run the complete test suite against real Docker services:

```bash
# Run all tests (Apache CRS)
./Test-Integration.ps1

# Same suite against nginx CRS
./Test-Integration.ps1 -ComposeFile ./docker-compose.test.nginx.yml

# Keep services running for debugging
./Test-Integration.ps1 -SkipDockerCleanup
```

**Prerequisites:** Docker, Docker Compose, PowerShell 7+

### Unit Tests

```bash
# Run unit tests
go test -v

# Run with coverage
go test -v -cover
```

### Performance Benchmarks

```bash
# Local benchmarks
go test -bench=. -benchmem

# Integration performance testing
docker compose -f docker-compose.test.yml up -d
go test -bench=BenchmarkProtectedEndpoint -benchmem
```

## ⚙️ Configuration

```yaml
http:
  middlewares:
    waf-middleware:
      plugin:
        modsecurity:
          #-------------------------------
          # Basic Configuration
          #-------------------------------
          modSecurityUrl: "http://modsecurity:80"
          # REQUIRED: URL of the ModSecurity container
          # This is the endpoint where the plugin will forward requests for security analysis
          # Examples:
          # - "http://modsecurity:80" (Docker service name)
          # - "http://localhost:8080" (Local development)
          # - "https://waf.example.com" (External service)
          
          logLevel: info
          # OPTIONAL: Plugin-owned log level (Traefik --log.level does not reach this middleware)
          # Default: info
          # Accepted: debug, info, warn, error
          # error: cannot read body, cannot reach ModSecurity
          # warn: health trip (expected backoff)
          # info: health backoff expiry (default; production-quiet)
          # debug: also reclaim_put / reclaim_bind / reclaim_dispose
          # Invalid values fail plugin construction
          
          timeoutMillis: 2000
          # OPTIONAL: Timeout in milliseconds for ModSecurity requests
          # Default: 2000ms (2 seconds)
          # This controls how long the plugin waits for ModSecurity to respond
          # Increase for slow ModSecurity instances or large payloads
          # Set to 0 for no timeout (not recommended in production)
          
          unhealthyWafBackOffPeriodSecs: 30
          # OPTIONAL: Backoff period in seconds when ModSecurity is unavailable
          # Default: 0 (return 502 Bad Gateway immediately)
          # When ModSecurity is down, this plugin can temporarily bypass it
          # Set to 0 to disable bypass (always return 502 when WAF is down)
          # Set to 30+ seconds for production environments with automatic failover
          
          modSecurityStatusRequestHeader: "X-Waf-Status"
          # OPTIONAL: Header name to add to requests for logging purposes
          # Default: empty (no header added)
          # This header is added to the REQUEST (not response) for Traefik access logs
          # Header values:
          # - "blocked" when the sidecar returns 4xx (security block)
          # - "error" when the sidecar is unreachable or returns 5xx
          # - "unhealthy" when ModSecurity is down and backoff is already tripped
          # - "cannotforward" when request forwarding fails
          # Configure Traefik access logs to capture this header:
          # accesslog.fields.headers.names.X-Waf-Status=keep
          
          #-------------------------------
          # Advanced Transport Configuration
          #-------------------------------
          # These parameters fine-tune HTTP client behavior for high-load scenarios
          # Leave at defaults unless you're experiencing performance issues
          
          maxConnsPerHost: 100
          # OPTIONAL: Maximum concurrent connections per ModSecurity host
          # Default: 0 (unlimited connections)
          # Controls connection pool size to prevent overwhelming ModSecurity
          # Recommended: 50-200 for most environments
          # Set to 0 for unlimited (original behavior)
          
          maxIdleConnsPerHost: 10
          # OPTIONAL: Maximum idle connections to keep per ModSecurity host
          # Default: 0 (unlimited idle connections)
          # Idle connections are kept alive for reuse, reducing connection overhead
          # Recommended: 5-20 for most environments
          # Set to 0 for unlimited (original behavior)
          
          responseHeaderTimeoutMillis: 5000
          # OPTIONAL: Timeout for waiting for response headers from ModSecurity
          # Default: 0 (no timeout)
          # This is different from timeoutMillis - it only waits for headers, not full response
          # Useful for detecting slow ModSecurity instances quickly
          # Set to 0 to disable (original behavior)
          
          expectContinueTimeoutMillis: 1000
          # OPTIONAL: Timeout for Expect: 100-continue handshake
          # Default: 1000ms (1 second)
          # Used when sending large payloads - ModSecurity can reject before full upload
          # Increase for very large files or slow networks
          # This is the only parameter that has a non-zero default
          
          maxBodySizeBytes: 5242880
          # OPTIONAL: Maximum request body size in bytes
          # Default: 5242880 (5 MB)
          # Security feature to prevent DoS attacks via large request bodies
          # Requests exceeding this limit will return HTTP 413 Request Entity Too Large
          # Set to 0 for unlimited (not recommended in production)
          # Common values:
          # - 1048576 (1 MB) for APIs
          # - 5242880 (5 MB) for general use
          # - 10485760 (10 MB) for file uploads
          # - 52428800 (50 MB) for large file processing
          
          ignoreBodyForVerbs: ["HEAD", "GET", "DELETE", "OPTIONS", "TRACE", "CONNECT"]
          # OPTIONAL: HTTP methods whose request body is not sent to ModSecurity
          # Default: ["HEAD", "GET", "DELETE", "OPTIONS", "TRACE", "CONNECT"]
          # The plugin still consumes that body so it cannot reach the backend.
          #
          # ⚠️  IMPORTANT: When a method is in this list, the request body is discarded.
          # It is not inspected by ModSecurity and it is not forwarded to the backend
          # or the next middleware, including when the WAF is unhealthy and the request
          # fail-opens. Content-Length is cleared. Residual risk: an attack that exists
          # only in that body is never seen by the WAF.
          # To inspect and forward a body on one of these methods, remove the method
          # from this list. To reject any body on these methods, set ignoreBodyForVerbsDeny.
          
          ignoreBodyForVerbsDeny: false
          # OPTIONAL: Whether to reject requests with body for verbs in ignoreBodyForVerbs
          # Default: false
          # When true, reads one byte from the body and returns HTTP 400 if any data is present.
          # When false (default), the body is discarded and not forwarded (see ignoreBodyForVerbs).
          
          maxBodySizeBytesForPool: 4194304
          # OPTIONAL: Threshold above which to use ad-hoc allocation instead of pool
          # Default: 4194304 (4 MB)
          # Memory optimization: prevents pool pollution with large buffers
          # 
          # How it works:
          # - Checks Content-Length header before reading body
          # - If Content-Length <= threshold: uses pooled bytes.Buffer
          # - If Content-Length > threshold: uses io.ReadAll with ad-hoc allocation
          # - Large requests don't store body to avoid memory issues
          # 
          # Benefits:
          # - Keeps pool efficient for common small requests
          # - Prevents large buffers from staying in pool
          # - Reduces GC pressure from oversized pooled objects
          # - Optimizes memory usage patterns
```


## Local Development

See [docker-compose.local.yml](docker-compose.local.yml) for local development setup.

```bash
# Start development environment
docker-compose -f docker-compose.local.yml up

# Run tests before committing
go test -v && ./Test-Integration.ps1
```
