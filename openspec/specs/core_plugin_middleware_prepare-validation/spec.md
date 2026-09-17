# core_plugin_middleware_prepare-validation

## Purpose

Fails plugin construction when a numeric middleware field is negative or `modSecurityUrl` is not an absolute http/https WAF base with a host and no path.

## Requirements

### Requirement: Negative numeric fields fail prepare

Plugin construction SHALL fail when any of these middleware fields is negative: `timeoutMillis`, `unhealthyWafBackOffPeriodSecs`, `unhealthyWafFailureThreshold`, `unhealthyWafFailureWindowSecs`, `unhealthyWafFailureRatio`, `unhealthyWafMaxBackOffPeriodSecs`, `maxConnsPerHost`, `maxIdleConnsPerHost`, `responseHeaderTimeoutMillis`, `expectContinueTimeoutMillis`, `maxBodySizeBytes`, `maxBodySizeBytesForPool`. A zero value SHALL keep today’s meaning (CreateConfig default, or disabled when that field’s default is zero).

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

### Requirement: Remaining numeric fields fail prepare when negative

Plugin construction SHALL fail when any of these middleware fields is negative, in addition to the `timeoutMillis` and `maxBodySizeBytes` cases already specified: `unhealthyWafBackOffPeriodSecs`, `unhealthyWafFailureThreshold`, `unhealthyWafFailureWindowSecs`, `unhealthyWafFailureRatio`, `unhealthyWafMaxBackOffPeriodSecs`, `maxConnsPerHost`, `maxIdleConnsPerHost`, `responseHeaderTimeoutMillis`, `expectContinueTimeoutMillis`, `maxBodySizeBytesForPool`.

#### Scenario: Negative unhealthyWafBackOffPeriodSecs is rejected

- **WHEN** an operator sets `unhealthyWafBackOffPeriodSecs` to a negative number
- **THEN** plugin construction SHALL fail

#### Scenario: Negative unhealthyWafFailureThreshold is rejected

- **WHEN** an operator sets `unhealthyWafFailureThreshold` to a negative number
- **THEN** plugin construction SHALL fail

#### Scenario: Negative unhealthyWafFailureWindowSecs is rejected

- **WHEN** an operator sets `unhealthyWafFailureWindowSecs` to a negative number
- **THEN** plugin construction SHALL fail

#### Scenario: Negative unhealthyWafFailureRatio is rejected

- **WHEN** an operator sets `unhealthyWafFailureRatio` to a negative number
- **THEN** plugin construction SHALL fail

#### Scenario: Negative unhealthyWafMaxBackOffPeriodSecs is rejected

- **WHEN** an operator sets `unhealthyWafMaxBackOffPeriodSecs` to a negative number
- **THEN** plugin construction SHALL fail

#### Scenario: Negative maxConnsPerHost is rejected

- **WHEN** an operator sets `maxConnsPerHost` to a negative number
- **THEN** plugin construction SHALL fail

#### Scenario: Negative maxIdleConnsPerHost is rejected

- **WHEN** an operator sets `maxIdleConnsPerHost` to a negative number
- **THEN** plugin construction SHALL fail

#### Scenario: Negative responseHeaderTimeoutMillis is rejected

- **WHEN** an operator sets `responseHeaderTimeoutMillis` to a negative number
- **THEN** plugin construction SHALL fail

#### Scenario: Negative expectContinueTimeoutMillis is rejected

- **WHEN** an operator sets `expectContinueTimeoutMillis` to a negative number
- **THEN** plugin construction SHALL fail

#### Scenario: Negative maxBodySizeBytesForPool is rejected

- **WHEN** an operator sets `maxBodySizeBytesForPool` to a negative number
- **THEN** plugin construction SHALL fail

### Requirement: Explicit failure ratio must be in (0, 1)

When `unhealthyWafFailureRatio` is set to a value other than zero, plugin construction SHALL fail unless that value is greater than 0 and less than 1. Zero SHALL mean the packaged default.

#### Scenario: Ratio 1 is rejected

- **WHEN** an operator sets `unhealthyWafFailureRatio` to 1
- **THEN** plugin construction SHALL fail

#### Scenario: Ratio 0.5 is accepted

- **WHEN** an operator sets `unhealthyWafFailureRatio` to 0.5 and a valid `modSecurityUrl`
- **THEN** plugin construction SHALL succeed

### Requirement: Explicit max backoff must be at least the base

When `unhealthyWafMaxBackOffPeriodSecs` is set to a value other than zero, plugin construction SHALL fail unless that value is greater than or equal to `unhealthyWafBackOffPeriodSecs`.

#### Scenario: Max below base is rejected

- **WHEN** the operator sets `unhealthyWafBackOffPeriodSecs` to 10
- **AND** sets `unhealthyWafMaxBackOffPeriodSecs` to 5
- **THEN** plugin construction SHALL fail
