# add-bypass-routes

I need a new config to allow admins to bypass the WAF. It needs particular attention to performance.

Someone attempted something similar in: https://github.com/DNAstack/traefik-modsecurity-plugin/commit/04c04549f54f0bb0f34330393669b63f5fd1be05 but the matchesBypassRule lookup does not scale and does not perform well, we should use only ONE lookup to find the regex that needs to be applied, so the compiled rules should be in a map of VERB -> RULE.

In terms of configuration, what we can do is CONCATENATE all regex expression (escaped!) with | into a single expression, and only store that compiled expression.

The user facing surface of the referenced commit looks good to me, but not the internals.

About the header that should be add for waf-state in case it is skipped by regex, it should be "bypassrule"
