# Replace custom WAF health tracker with upstream backendbackoff

Replace the custom health probe in pkg/health with the one from upstream https://github.com/david-garcia-garcia/traefik-middleware-utilities. Extra public config knobs may be required so this plugin can keep current WAF-backoff behavior (or expose knobs the upstream probe needs). Test coverage must be thorough.
