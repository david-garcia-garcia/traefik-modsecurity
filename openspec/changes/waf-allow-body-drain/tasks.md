## 1. Drain

- [x] 1.1 On the allow path in `pkg/modsecurity/serve.go`, copy the sidecar body to `io.Discard` through a 256 KiB `LimitReader` before `next.ServeHTTP`. Keep the existing deferred `Close`.
- [x] 1.2 Name the cap so the next reader sees 256 KiB, not a magic number.

## 2. Test

- [x] 2.1 Add a `pkg/modsecurity` test that serves a whoami-sized 200 from `httptest`, counts `ConnState` `StateNew`, and asserts one new connection across sequential allow-path GETs.
- [x] 2.2 Run `go test ./pkg/modsecurity ./...` and record the result.

## 3. Usage

- [x] 3.1 After code review, update `knowledge/devdocs/core_plugin_middleware.md` if the allow-path contract is still silent on drain (devdocs-impact owns the produce).
