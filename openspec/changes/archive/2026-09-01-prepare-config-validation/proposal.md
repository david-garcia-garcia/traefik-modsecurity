## Why

`Prepare` only rejects an empty `modSecurityUrl` and an unknown `logLevel`. Negative numeric fields pass through: a negative `maxBodySizeBytes` skips `http.MaxBytesReader` and the request body is read with no cap. An unparsed WAF URL fails on every request (502 / `cannotforward`) instead of at plugin construction. A trailing slash on the base URL concatenates to `//path`.

## What Changes

- **BREAKING** (misconfiguration only): `Prepare` rejects every numeric config field that is negative.
- **BREAKING** (misconfiguration only): `Prepare` parses `modSecurityUrl` and requires an absolute `http` or `https` URL with a host and no path (query, userinfo, and fragment rejected). A lone trailing slash is trimmed before store.
- Valid existing examples (`http://waf`, `http://waf:8080`, `https://waf.example.com`, `httptest.Server.URL`) stay accepted.
- Tests cover negatives, bad URLs, trailing-slash trim, and happy-path URLs.

## Capabilities

### New Capabilities

- `core_plugin_middleware_prepare-validation`: Startup validation in `Prepare` for numeric fields and `ModSecurityUrl`.

### Modified Capabilities

None.

## Impact

- `pkg/modsecurity/config.go` (`Prepare`)
- `pkg/modsecurity/config_test.go`
- Operator docs / `knowledge/devdocs/core_plugin_middleware.md` (Prepare contract)
- Operators with a negative number or a non-absolute / path-bearing `modSecurityUrl` fail plugin construction after upgrade
