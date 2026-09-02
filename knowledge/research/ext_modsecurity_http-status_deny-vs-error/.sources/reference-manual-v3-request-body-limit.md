# Extract: SecRequestBodyLimit / SecRequestBodyNoFilesLimit (v3.x)

Source: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v3.x)
Retrieved: 2026-09-02

## SecRequestBodyLimit

Configures the maximum request body size ModSecurity will accept for buffering.

Default: 134217728 (131072 KB)

Anything over the limit will be rejected with status code 413 (Request Entity Too Large). There is a hard limit of 1 GB.

## SecRequestBodyNoFilesLimit

Configures the maximum request body size ModSecurity will accept for buffering, excluding the size of any files being transported in the request.

Default: 1048576 (1 MB)

Anything over the limit will be rejected with status code 413 (Request Entity Too Large). There is a hard limit of 1 GB.

## SecRequestBodyLimitAction

Controls what happens once a request body limit, configured with SecRequestBodyLimit, is encountered.

Syntax: `SecRequestBodyLimitAction Reject|ProcessPartial`

When the SecRuleEngine is set to DetectionOnly, SecRequestBodyLimitAction is automatically set to ProcessPartial.
