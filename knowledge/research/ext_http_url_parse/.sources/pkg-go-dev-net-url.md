---
url: https://pkg.go.dev/net/url#Parse
title: net/url Parse / URL / IsAbs
fetched: 2026-09-01
authority: official
---

Parse parses a raw url into a URL structure. The url may be relative (a path, without a host) or absolute (starting with a scheme). Trying to parse a hostname and path without a scheme is invalid but may not necessarily return an error, due to parsing ambiguities.

URL fields: Scheme, Host ("host" or "host:port"), Path (decoded; relative paths may omit leading slash).

IsAbs reports whether the URL is absolute. Absolute means that it has a non-empty scheme.
