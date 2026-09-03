---
url: https://github.com/golang/go/blob/go1.21.13/src/regexp/syntax/doc.go
title: src/regexp/syntax/doc.go
fetched: 2026-09-03
authority: source
ref: golang/go@go1.21.13:src/regexp/syntax/doc.go
---

Generated from the RE2 distribution (`mksyntaxgo`). Same table as https://pkg.go.dev/regexp/syntax.

Composites (Perl flag — `regexp.Compile` default):

- `xy` — x followed by y
- `x|y` — x or y (prefer x)

Grouping:

- `(re)` — numbered capturing group (submatch)
- `(?:re)` — non-capturing group

Empty strings: `^` beginning of text (or line if `m`); `$` end of text (or line if `m`); `\A` / `\z` text bounds.

Package regexp overview cites this syntax (`golang.org/s/re2syntax`).
