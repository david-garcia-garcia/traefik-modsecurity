## 1. Config surface

- [ ] 1.1 Add `LogLevel` to `Config` with `json:"logLevel,omitempty"`. Default `info` in `CreateConfig`.
- [ ] 1.2 In `Prepare`, treat empty as `info`, lowercase accepted values `debug|info|warn|error`, reject anything else.

## 2. One logger

- [ ] 2.1 Add a constructor that builds `*slog.Logger` (text handler, `os.Stdout`, min level from prepared `logLevel`).
- [ ] 2.2 Store that logger on `Plugin`. Change `pkg/health.Tracker` to take `*slog.Logger`. Trip at error; backoff expired at info.
- [ ] 2.3 In `bindPlugin`, build the logger after Prepare, pass the same pointer to `reclaim.Open` and `modsecurity.New`. Remove `io.Discard`.
- [ ] 2.4 Emit ServeHTTP failure lines at error on the Plugin logger (body too large, fail to read, fail to prepare/send, verb-body reject).

## 3. Tests and docs

- [ ] 3.1 Go tests: default `info`, case normalize, invalid rejected, hash changes when only `logLevel` differs, info hides reclaim Debug, debug allows it.
- [ ] 3.2 Update health tracker tests to pass a slog logger.
- [ ] 3.3 Document `logLevel` in `README.md`. Set `logLevel=debug` on at least one middleware in `docker-compose.test.yml` (no new Pester; helpers only read access.log).
- [ ] 3.4 Run existing Go unit tests and report the result.
