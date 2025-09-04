# 🛡️ Traefik ModSecurity Plugin

[![Build Status](https://github.com/david-garcia-garcia/traefik-modsecurity/actions/workflows/build.yml/badge.svg)](https://github.com/david-garcia-garcia/traefik-modsecurity/actions/workflows/build.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/david-garcia-garcia/traefik-modsecurity)](https://goreportcard.com/report/github.com/david-garcia-garcia/traefik-modsecurity)
[![Go Version](https://img.shields.io/github/go-mod/go-version/david-garcia-garcia/traefik-modsecurity)](https://img.shields.io/github/go-mod/go-version/david-garcia-garcia/traefik-modsecurity)
[![Latest Release](https://img.shields.io/github/v/release/david-garcia-garcia/traefik-modsecurity?sort=semver)](https://github.com/david-garcia-garcia/traefik-modsecurity/releases/latest)
[![License](https://img.shields.io/badge/license-Apache%202.0-brightgreen.svg)](LICENSE)

A Traefik plugin that integrates with [OWASP ModSecurity Core Rule Set (CRS)](https://github.com/coreruleset/coreruleset) to provide Web Application Firewall (WAF) protection for your applications.

> [!WARNING] ** Traefik Security Trifecta**
> 
> **Traefik Security Trifecta**: the three basic modules you need to secure your Traefik ingress:
> 
> - **🌍 Geoblock**: [david-garcia-garcia/traefik-geoblock](https://github.com/david-garcia-garcia/traefik-geoblock) - Block or allow requests based on IP geolocation
> - **🛡️ CrowdSec**: [maxlerebourg/crowdsec-bouncer-traefik-plugin](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/tree/main) - Real-time threat intelligence and automated blocking
> - **🔒 ModSecurity CRS**: [david-garcia-garcia/traefik-modsecurity](https://github.com/david-garcia-garcia/traefik-modsecurity) - Web Application Firewall with OWASP Core Rule Set

- [Traefik Modsecurity Plugin](#traefik-modsecurity-plugin)
    - [Demo](#demo)
    - [Usage (docker-compose.yml)](#usage-docker-composeyml)
    - [How it works](#how-it-works)
    - [Local development (docker-compose.local.yml)](#local-development-docker-composelocalyml)

## Demo

Demo with WAF intercepting relative access in query param.

![Demo](./img/waf.gif)

## Usage (docker-compose.yml)

See [docker-compose.yml](docker-compose.yml)

1. docker-compose up
2. Go to http://localhost/website, the request is received without warnings
3. Go to http://localhost/website?test=../etc, the request is intercepted and returned with 403 Forbidden by
   owasp/modsecurity
4. You can you bypass the WAF and check attacks at http://localhost/bypass?test=../etc

## How it works

This is a very simple plugin that proxies the query to the owasp/modsecurity apache container.

The plugin checks that the response from the waf container hasn't an http code > 400 before forwarding the request to
the real service.

If it is > 400, then the error page is returned instead.

The *dummy* service is created so the waf container forward the request to a service and respond with 200 OK all the
time.

## Configuration

This plugin supports these configuration:

### Basic Configuration

* `modSecurityUrl`: (**mandatory**) it's the URL for the owasp/modsecurity container.
* `timeoutMillis`: (optional) timeout in milliseconds for the http client to talk with modsecurity container. (default 2000ms)
* `unhealthyWafBackOffPeriodSecs` (optional) the period, in seconds, to backoff if calls to modsecurity fail. Default to 0. Default behaviour is to send a 502 Bad Gateway when there are problems communicating with modsec.
* `modSecurityStatusRequestHeader`: (optional) name of the header to add to the request when requests are blocked by ModSecurity (for logging purposes). The header value will contain the HTTP status code returned by ModSecurity. Default is empty (no header added).

### Advanced Transport Configuration

These parameters allow fine-tuning of the HTTP client behavior for high-load scenarios:

* `maxConnsPerHost`: (optional) maximum number of concurrent connections allowed per ModSecurity host. Set to 0 for unlimited connections (default: 0 - unlimited, original behavior).
* `maxIdleConnsPerHost`: (optional) maximum number of idle connections to keep per ModSecurity host. Set to 0 for unlimited idle connections (default: 0 - unlimited, original behavior).
* `responseHeaderTimeoutMillis`: (optional) timeout in milliseconds for waiting for response headers from ModSecurity. Set to 0 for no timeout (default: 0 - no timeout, original behavior).
* `expectContinueTimeoutMillis`: (optional) timeout in milliseconds for Expect: 100-continue handshake. Used for large payload uploads (default: 1000ms).


## Local development (docker-compose.local.yml)

See [docker-compose.local.yml](docker-compose.local.yml)

`docker-compose -f docker-compose.local.yml up` to load the local plugin
