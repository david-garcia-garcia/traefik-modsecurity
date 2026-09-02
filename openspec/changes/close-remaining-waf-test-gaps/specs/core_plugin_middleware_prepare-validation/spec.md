## ADDED Requirements

### Requirement: Remaining numeric fields fail prepare when negative

Plugin construction SHALL fail when any of these middleware fields is negative, in addition to the `timeoutMillis` and `maxBodySizeBytes` cases already specified: `unhealthyWafBackOffPeriodSecs`, `unhealthyWafFailureThreshold`, `unhealthyWafFailureWindowSecs`, `maxConnsPerHost`, `maxIdleConnsPerHost`, `responseHeaderTimeoutMillis`, `expectContinueTimeoutMillis`, `maxBodySizeBytesForPool`.

#### Scenario: Negative unhealthyWafBackOffPeriodSecs is rejected

- **WHEN** an operator sets `unhealthyWafBackOffPeriodSecs` to a negative number
- **THEN** plugin construction SHALL fail

#### Scenario: Negative unhealthyWafFailureThreshold is rejected

- **WHEN** an operator sets `unhealthyWafFailureThreshold` to a negative number
- **THEN** plugin construction SHALL fail

#### Scenario: Negative unhealthyWafFailureWindowSecs is rejected

- **WHEN** an operator sets `unhealthyWafFailureWindowSecs` to a negative number
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
