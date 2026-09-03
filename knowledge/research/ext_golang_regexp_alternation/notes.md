# regexp Compile alternation

Go’s `regexp` package is RE2 (not PCRE). `Compile` parses a pattern and returns `(*Regexp, error)`. `QuoteMeta` turns a **literal string** into a pattern that matches that text; it does not preserve an already-valid regex. Several already-valid pattern strings join safely as `(?:p1)|(?:p2)|…`. `Regexp.MatchString` is unanchored (substring search). Invalid patterns fail at `Compile`.

## Compile and invalid patterns

`Compile(expr)` parses `expr` with Perl/RE2 flags and returns a `*Regexp` or an error. The implementation calls `syntax.Parse`; a bad pattern never produces a usable `*Regexp`.

Owner: [pkg.go.dev/regexp#Compile](https://pkg.go.dev/regexp#Compile) and `golang/go@go1.21.13:src/regexp/regexp.go` (`Compile` → `compile` → `syntax.Parse`).

The package-level `MatchString` compiles first. Official example: `regexp.MatchString("a(b", "seafood")` returns `false` and `error parsing regexp: missing closing ): \`a(b\``.

`MustCompile` is the same parse but **panics** on error (init-time globals only).

Extracts: `.sources/pkg-go-dev-regexp.md`, `.sources/regexp.go.md`

## QuoteMeta is literal-escaping, not “keep this regex”

`QuoteMeta(s)` “escapes all regular expression metacharacters inside the argument text; the returned string is a regular expression matching the **literal** text.”

Metacharacters escaped (source `init`): `\ . + * ? ( ) | [ ] { } ^ $`. Official example: `QuoteMeta("Escaping symbols like: .+*?()|[]{}^$")` → `Escaping symbols like: \.\+\*\?\(\)\|\[\]\{\}\^\$`.

So `QuoteMeta` does turn a string into a regex for that literal. Applying it to an already-valid pattern **destroys** the pattern: `|`, `()`, `+`, etc. become literal characters.

Use `QuoteMeta` only when the input is a literal (path fragment, verb). Do not `QuoteMeta` user-supplied regex strings before `Compile`.

Owner: [pkg.go.dev/regexp#QuoteMeta](https://pkg.go.dev/regexp#QuoteMeta) and `…@go1.21.13:src/regexp/regexp.go` (`QuoteMeta`, `special`, `specialBytes`).

Extracts: `.sources/pkg-go-dev-regexp.md`, `.sources/regexp.go.md`

## Alternation and joining already-valid patterns

RE2 composites (Perl flag, the `Compile` default):

- `xy` — `x` followed by `y` (concatenation)
- `x|y` — `x` or `y` (prefer `x`)
- `(?:re)` — non-capturing group
- `(re)` — numbered capturing group

Owner: [pkg.go.dev/regexp/syntax](https://pkg.go.dev/regexp/syntax) / `golang/go@go1.21.13:src/regexp/syntax/doc.go` (generated from the RE2 distribution). Package `regexp` points at the same syntax (`https://golang.org/s/re2syntax`).

Extract: `.sources/syntax-doc.go.md`

Concatenation binds tighter than `|`. Joining raw strings `ab` and `cd` as `abcd` means “ab then cd”, not “ab or cd”. Joining `foo` and `bar|baz` as `foobar|baz` is the same class of bug.

Safe combine of already-valid pattern strings `p1…pn` (inference from those two composite rules):

```
(?:p1)|(?:p2)|(?:p3)
```

Each `(?:…)` keeps that pattern a single alternative. Non-capturing avoids renumbering `(re)` groups across the join. Then one `Compile` of the combined string.

Empty `expr`: `Compile("")` succeeds. `MatchString` then reports a match in every string (empty match at the start).

## MatchString is unanchored

`func (re *Regexp) MatchString(s string) bool` — “reports whether the string `s` **contains any match** of the regular expression `re`.”

Package-level `MatchString` is the same: official example `MatchString("foo.*", "seafood")` is `true`.

There is no implicit `^`/`$`. A path regexp `health` matches `/health`, `/unhealthy`, and `/health/ready`. Anchor in the pattern when a full-string match is required (`^…$`, or `\A`/`\z`).

Owner: [pkg.go.dev/regexp#Regexp.MatchString](https://pkg.go.dev/regexp#Regexp.MatchString) and `…@go1.21.13:src/regexp/regexp.go` (`MatchString` → `doMatch`).

Extracts: `.sources/pkg-go-dev-regexp.md`, `.sources/regexp.go.md`
