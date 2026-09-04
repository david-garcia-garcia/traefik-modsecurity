---
url: https://github.com/golang/go/blob/go1.21.13/src/regexp/regexp.go
title: src/regexp/regexp.go
fetched: 2026-09-03
authority: source
ref: golang/go@go1.21.13:src/regexp/regexp.go
---

`Compile` calls `compile(expr, syntax.Perl, false)`.

`compile` starts with `syntax.Parse(expr, mode)` and returns that error if parse fails. Then `Simplify` + `syntax.Compile`.

`MatchString` on `*Regexp`: “reports whether the string s contains any match” → `doMatch(nil, nil, s)`.

`QuoteMeta` comment matches the official docs (literal-text regex). `init` marks these ASCII bytes as special: `\ . + * ? ( ) | [ ] { } ^ $`. Each special byte is prefixed with `\` in the returned string. No-meta input is returned unchanged.

Product `go.mod` is `go 1.21`; this extract is the go1.21.13 tag of the same API.
