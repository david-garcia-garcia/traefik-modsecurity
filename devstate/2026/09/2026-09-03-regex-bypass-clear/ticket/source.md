# Make bypass pathRegexp unanchored matching obvious to operators

Source: chat-originated ticket. Review finding from `opus_review.md` § “Bypass path regexes are unanchored and matched against the decoded path”. Human override on the suggested fix.

## Review finding (verbatim gist)

`match` does `re.MatchString(req.URL.Path)`, which succeeds when the pattern occurs anywhere in the path, not as a prefix and not as a whole-path match. The doc comment on `BypassRule` (`config.go:18-19`) and the test fixtures (`bypass_test.go`) describe the feature as if it were prefix matching, and nothing in `compileBypassByMethod` anchors the operator's pattern. On top of that, the match runs against `req.URL.Path`, which is percent-decoded and not dot-segment-normalized, while what actually reaches the backend is the escaped, un-normalized target.

Trigger examples from the review: an operator adds `{pathRegexp: "/health"}` or `{method: GET, pathRegexp: "/search/v1/statement/executing/"}`. An attacker then requests `GET /index.php/health?id=1'+OR+1=1--`, or `GET /health/../index.php?...`, or `GET /health%2f..%2fadmin`. All three decode to a `URL.Path` containing the allowlisted substring, so the bypass fires; the backend then serves the real target.

Review fix sketch (not taken as-is): wrap each grouped alternative as `\A(?:pattern)` for prefix semantics (or `\A(?:pattern)\z` for exact), and match against a normalized path / refuse bypass when `.` / `..` segments or RawPath vs EscapedPath disagree.

## Human decision

Do **not** anchor by default. Anchoring (`^` / `$` / `\A` / `\z`) is the operator’s responsibility. What this ticket asks for is **clear documentation** so the operator knows `pathRegexp` is unanchored RE2 `MatchString` and there is no confusion with prefix or exact-path matching.
