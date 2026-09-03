package modsecurity

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// bypassStatusToken is the modSecurityStatusRequestHeader value when a bypass rule matched.
const bypassStatusToken = "bypassrule"

// matchAllBypassPath matches every path. Used when a method-only (empty pathRegexp) rule is present.
var matchAllBypassPath = regexp.MustCompile(`(?s).*`)

// compiledBypass is one regexp per HTTP method plus the fallback for methods not in the map.
type compiledBypass struct {
	byMethod  map[string]*regexp.Regexp
	anyMethod *regexp.Regexp
}

// compileBypassByMethod joins path regexes per uppercase method into one compiled expression each.
// Path-only rules (empty method) are merged into every method entry and into anyMethod.
func compileBypassByMethod(rules []BypassRule) (compiledBypass, error) {
	if len(rules) == 0 {
		return compiledBypass{}, nil
	}

	byMethodParts := make(map[string][]string)
	alwaysMethod := make(map[string]bool)
	var anyParts []string
	alwaysAny := false

	for _, rule := range rules {
		method := strings.ToUpper(strings.TrimSpace(rule.Method))
		pattern := rule.PathRegexp
		if pattern != "" {
			if _, err := regexp.Compile(pattern); err != nil {
				return compiledBypass{}, fmt.Errorf("invalid bypass rule pathRegexp %q: %w", pattern, err)
			}
		}
		if method == "" && pattern == "" {
			alwaysAny = true
			continue
		}
		if pattern == "" {
			alwaysMethod[method] = true
			continue
		}
		grouped := "(?:" + pattern + ")"
		if method == "" {
			anyParts = append(anyParts, grouped)
			continue
		}
		byMethodParts[method] = append(byMethodParts[method], grouped)
	}

	anyRegexp, err := joinBypassPatterns(anyParts)
	if err != nil {
		return compiledBypass{}, err
	}
	if alwaysAny {
		anyRegexp = matchAllBypassPath
	}

	byMethod := make(map[string]*regexp.Regexp, len(byMethodParts)+len(alwaysMethod))
	for method := range byMethodParts {
		re, err := compiledMethodRegexp(alwaysAny, alwaysMethod[method], byMethodParts[method], anyParts)
		if err != nil {
			return compiledBypass{}, err
		}
		byMethod[method] = re
	}
	for method := range alwaysMethod {
		if _, exists := byMethod[method]; exists {
			continue
		}
		re, err := compiledMethodRegexp(alwaysAny, true, nil, anyParts)
		if err != nil {
			return compiledBypass{}, err
		}
		byMethod[method] = re
	}

	return compiledBypass{byMethod: byMethod, anyMethod: anyRegexp}, nil
}

// compiledMethodRegexp returns the one regexp used for a single HTTP method.
func compiledMethodRegexp(alwaysAny, methodAlways bool, methodParts, anyParts []string) (*regexp.Regexp, error) {
	if alwaysAny || methodAlways {
		return matchAllBypassPath, nil
	}
	parts := make([]string, 0, len(methodParts)+len(anyParts))
	parts = append(parts, methodParts...)
	parts = append(parts, anyParts...)
	return joinBypassPatterns(parts)
}

// joinBypassPatterns compiles already-grouped alternatives joined with |.
func joinBypassPatterns(parts []string) (*regexp.Regexp, error) {
	if len(parts) == 0 {
		return nil, nil
	}
	compiled, err := regexp.Compile(strings.Join(parts, "|"))
	if err != nil {
		return nil, fmt.Errorf("invalid bypass rule pathRegexp join: %w", err)
	}
	return compiled, nil
}

// match reports whether req method+path hits the compiled allowlist. One map get, then at most one MatchString.
func (c compiledBypass) match(req *http.Request) bool {
	if req == nil {
		return false
	}
	re := c.byMethod[strings.ToUpper(req.Method)]
	if re == nil {
		re = c.anyMethod
	}
	if re == nil {
		return false
	}
	path := ""
	if req.URL != nil {
		path = req.URL.Path
	}
	return re.MatchString(path)
}
