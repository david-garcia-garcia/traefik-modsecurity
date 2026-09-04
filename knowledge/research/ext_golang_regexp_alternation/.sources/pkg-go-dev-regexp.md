---
url: https://pkg.go.dev/regexp
title: regexp package
fetched: 2026-09-03
authority: official
---

Package regexp implements regular expression search. Syntax is RE2 (`https://golang.org/s/re2syntax`), except `\C`. Overview of the syntax: package `regexp/syntax`.

`func Compile(expr string) (*Regexp, error)` — parses a regular expression and returns, if successful, a Regexp. Leftmost-first match.

`func MustCompile(str string) *Regexp` — like Compile but panics if the expression cannot be parsed.

`func QuoteMeta(s string) string` — “returns a string that escapes all regular expression metacharacters inside the argument text; the returned string is a regular expression matching the literal text.”

Example output: `QuoteMeta("Escaping symbols like: .+*?()|[]{}^$")` → `Escaping symbols like: \.\+\*\?\(\)\|\[\]\{\}\^\$`.

`func MatchString(pattern string, s string) (matched bool, err error)` — “reports whether the string s contains any match of the regular expression pattern.” Example: `foo.*` vs `seafood` → `true`; `a(b` vs `seafood` → `false, error parsing regexp: missing closing ): \`a(b\``.

`func (re *Regexp) MatchString(s string) bool` — “reports whether the string s contains any match of the regular expression re.”
