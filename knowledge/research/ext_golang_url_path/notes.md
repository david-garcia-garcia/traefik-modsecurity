# URL Path RawPath EscapedPath

Go `net/url` `URL.Path` is the **decoded** path. `RawPath` is an optional encoding hint. `EscapedPath()` is the API that reconstructs an escaped path. `Parse` / `ParseRequestURI` do **not** collapse `.` or `..` segments on `Path`. Product `go.mod` is `go 1.21`; extracts are pinned to `go1.21.13`.

## Path is decoded; slashes from `/` and `%2f` look the same

`URL.Path` is stored in decoded form. Official example: `/%47%6f%2f` becomes `/Go/`. After parse it is impossible to tell which slashes in `Path` were literal `/` and which were `%2f`.

Owner: [pkg.go.dev/net/url@go1.21.13](https://pkg.go.dev/net/url@go1.21.13) (`URL` type comment) and `golang/go@go1.21.13:src/net/url/url.go` (`URL` struct comment).

`Parse` and `ParseRequestURI` both reach `setPath` on the path remainder. `setPath` unescapes with `encodePath` and assigns that string to `Path`.

Owner: `…@go1.21.13:src/net/url/url.go` (`Parse` → `parse` → `setPath`; `ParseRequestURI` → `parse` → `setPath`).

Extracts: `.sources/pkg-go-dev-net-url.md`, `.sources/url.go.md`

## RawPath is only set when the default escape differs

`RawPath` is “an optional field which is only set when the default encoding of Path is different from the escaped path.” Field comment: “encoded path hint (see EscapedPath method).”

`setPath` keeps that invariant:

- `setPath("/foo/bar")` → `Path="/foo/bar"`, `RawPath=""`
- `setPath("/foo%2fbar")` → `Path="/foo/bar"`, `RawPath="/foo%2fbar"`

If `escape(path, encodePath)` equals the raw escaped input, `RawPath` stays empty so callers do not rely on it.

Owner: [pkg.go.dev/net/url@go1.21.13](https://pkg.go.dev/net/url@go1.21.13) (`URL` type comment) and `…@go1.21.13:src/net/url/url.go` (`setPath`).

Extracts: `.sources/pkg-go-dev-net-url.md`, `.sources/url.go.md`

## EscapedPath, not RawPath

`EscapedPath` “returns the escaped form of u.Path.” There are multiple possible escaped forms. It returns `u.RawPath` when that value is a valid escaping of `u.Path`; otherwise it ignores `RawPath` and computes an escape. `String` and `RequestURI` use `EscapedPath`. Official guidance: call `EscapedPath` instead of reading `RawPath` directly.

Owner: [pkg.go.dev/net/url@go1.21.13#URL.EscapedPath](https://pkg.go.dev/net/url@go1.21.13#URL.EscapedPath) and `…@go1.21.13:src/net/url/url.go` (`EscapedPath`).

Extracts: `.sources/pkg-go-dev-net-url.md`, `.sources/url.go.md`

## Parse does not slash-normalize `.` / `..`

Official docs do not say `Parse` collapses `.` or `..`. Cleaning is documented on other APIs:

- `URL.JoinPath` / `JoinPath` — “the resulting path cleaned of any `./` or `../` elements”
- `ResolveReference` — RFC 3986 §5.2; implementation calls `resolvePath`, which drops `.` and applies `..`

`setPath` only unescapes. It does not call `resolvePath` or `path.Join`. So a parsed `Path` can still contain `.` and `..` segments. `%2f` in the raw path becomes `/` in `Path` and does not change that: the decoded `..` still stays.

Owner of JoinPath cleaning and ResolveReference: [pkg.go.dev/net/url@go1.21.13#URL.JoinPath](https://pkg.go.dev/net/url@go1.21.13#URL.JoinPath), [pkg.go.dev/net/url@go1.21.13#URL.ResolveReference](https://pkg.go.dev/net/url@go1.21.13#URL.ResolveReference).

Owner of “Parse only unescapes”: `…@go1.21.13:src/net/url/url.go` (`setPath`, `resolvePath` used from `ResolveReference` only).

This-run `url.Parse` on the worktree toolchain (Go 1.25.6; same `Path`/`RawPath`/`EscapedPath` comments as go1.21.13):

```
raw="/health/../index.php" Path="/health/../index.php" RawPath="" EscapedPath="/health/../index.php"
raw="/health%2f..%2fadmin" Path="/health/../admin" RawPath="/health%2f..%2fadmin" EscapedPath="/health%2f..%2fadmin"
```

Literal `..` stays on `Path`. Encoded slashes decode on `Path` and keep `RawPath` / `EscapedPath` in the original encoding. That matches `setPath` and the official “decoded form” / “default encoding differs” rules.

Authority for “Parse does not collapse `..`”: `source` (`setPath`) plus this measurement. Official docs do not contradict; they only document cleaning on `JoinPath` and `ResolveReference`.

Extracts: `.sources/pkg-go-dev-net-url.md`, `.sources/url.go.md`
