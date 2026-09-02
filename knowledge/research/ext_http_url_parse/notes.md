# Go net/url Parse

`url.Parse` accepts a relative path or an absolute URL (starts with a scheme). A hostname-plus-path with no scheme is invalid but may not return an error. `URL.IsAbs` is true when Scheme is non-empty. `Host` is `host` or `host:port`. `Path` is the decoded path and is `/` when the raw URL ends with a slash after the authority.

Owner: [net/url Parse](https://pkg.go.dev/net/url#Parse), [URL](https://pkg.go.dev/net/url#URL), [URL.IsAbs](https://pkg.go.dev/net/url#URL.IsAbs).

Extract: `.sources/pkg-go-dev-net-url.md`

## This product

`Prepare` must parse `ModSecurityUrl` and reject values that are not an absolute `http`/`https` URL with a host and no path. Usage: `knowledge/devdocs/core_plugin_middleware.md`.
