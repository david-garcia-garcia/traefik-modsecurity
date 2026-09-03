## Purpose

Fails plugin construction when a numeric middleware field is negative or `modSecurityUrl` is not an absolute http/https WAF base with a host and no path.

## ADDED Requirements

### Requirement: Negative numeric fields fail prepare

Plugin construction SHALL fail when any of these middleware fields is negative: `timeoutMillis`, `unhealthyWafBackOffPeriodSecs`, `unhealthyWafFailureThreshold`, `unhealthyWafFailureWindowSecs`, `maxConnsPerHost`, `maxIdleConnsPerHost`, `responseHeaderTimeoutMillis`, `expectContinueTimeoutMillis`, `maxBodySizeBytes`, `maxBodySizeBytesForPool`. A zero value SHALL keep today’s meaning (CreateConfig default, or disabled when that field’s default is zero).

#### Scenario: Negative maxBodySizeBytes is rejected

- **WHEN** an operator sets `maxBodySizeBytes` to a negative number
- **THEN** plugin construction SHALL fail

#### Scenario: Negative timeoutMillis is rejected

- **WHEN** an operator sets `timeoutMillis` to a negative number
- **THEN** plugin construction SHALL fail

#### Scenario: Zero timeoutMillis still defaults

- **WHEN** an operator omits `timeoutMillis` or sets it to 0
- **THEN** the prepared configuration SHALL use the CreateConfig default for `timeoutMillis`

### Requirement: ModSecurityUrl is an absolute http or https host with no path

Plugin construction SHALL fail when `modSecurityUrl` is empty, cannot be parsed as a URL, is not absolute, uses a scheme other than `http` or `https`, has no host, has a path other than a lone trailing slash, or has a query, userinfo, or fragment. A lone trailing slash SHALL be removed before the prepared value is stored. The stored base SHALL be the scheme, host, and optional port only.

#### Scenario: Missing scheme is rejected

- **WHEN** an operator sets `modSecurityUrl` to `waf:80`
- **THEN** plugin construction SHALL fail

#### Scenario: Path prefix is rejected

- **WHEN** an operator sets `modSecurityUrl` to `http://waf:80/modsec`
- **THEN** plugin construction SHALL fail

#### Scenario: Trailing slash is trimmed

- **WHEN** an operator sets `modSecurityUrl` to `http://waf:80/`
- **THEN** plugin construction SHALL succeed
- **AND** the prepared `modSecurityUrl` SHALL be `http://waf:80`

#### Scenario: Host-only http URL is accepted

- **WHEN** an operator sets `modSecurityUrl` to `http://waf` or `https://waf.example.com`
- **THEN** plugin construction SHALL succeed
