# Middleware Design Knowledge

> Maintained by: project team  
> Last updated: 2025-03-07

Traefik middleware lifecycle and design patterns that are easy to get wrong. This knowledge comes from experience and avoids common confusion.

---

## One middleware instance per route

**Fact:** A middleware instance is created **per route**. The constructor:

```go
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error)
```

is called **once per route** that uses this middleware. When the middleware configuration changes at runtime in Traefik, `New` is called again for every affected route.

**Implication:** Do not assume a single long-lived instance. Design for many instances; share state explicitly when it makes sense (see below).

---

## Constructor performance blocks Traefik startup

**Fact:** Middleware initialization is **linear and blocking**. Traefik does not serve routes until **all** middlewares for **all** routes have been initialized.

If a middleware has heavy initialization logic (e.g. connecting to a backend, loading large config, doing I/O), it can **block Traefik startup** entirely. Routes stay down until every middleware constructor returns.

**Implication:** Keep `New` fast. No slow I/O, no heavy parsing, no blocking network calls. Defer expensive work to first request, background goroutines, or lazy init — but be aware of the tradeoffs (e.g. first request latency).

---

## Global shared state is allowed and often advised

**Fact:** You can (and often should) preserve **global state** when it makes sense, instead of duplicating it per middleware instance.

**Pattern:** For components that are expensive or connection-based (e.g. a Redis client, an LAPI client), hash the settings (connection string, etc.) and keep a **global pool/cache** of instances. All middleware instances that share the same config use the same underlying component.

**Tradeoff:** When configuration changes at runtime, you may have **dangling instances** (old connections no longer used). This is expected and rare — it only happens on config change, not during normal operation. Prefer this over N independent instances per route.

**Example:** The CrowdSec bouncer middleware keeps LAPI communication, decision retrieval, etc. in a **global component** shared by all middleware instances.

**Go pattern for globals:** Use package-level variables and silence the linter where intentional:

```go
//nolint:gochecknoglobals
var (
	isStartup               = true
	isCrowdsecStreamHealthy = true
	updateFailure           int64
	streamTicker            chan bool
	metricsTicker           chan bool
	lastMetricsPush         time.Time
	blockedRequests         int64
)
```

### Why this matters here

This plugin (`traefik_modsecurity`) proxies to an external WAF. If we had one HTTP client per route, we could end up with hundreds of connections to the same ModSecurity URL. Prefer a shared client pool keyed by config (e.g. `ModSecurityUrl` + timeouts) so that many routes share the same connection pool and initialization cost.
