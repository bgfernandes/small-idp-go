// Package scope provides functions for parsing and validating scope values.
package scope

import (
	"errors"
	"slices"
	"strings"
)

// errUnknownOrMalformedScope is returned when a scope is unknown or malformed.
var errUnknownOrMalformedScope = errors.New("unknown or malformed scope")

// Parse validates a string as a space-separated list of scope values and checks if every scope
// belongs to the given set, and returns a deduplicated list of scope values. If the input is empty,
// it will default to the given allowed scopes.
func Parse(s string, allowedScopes []string) ([]string, error) {
	if s == "" {
		return allowedScopes, nil
	}

	scopes := strings.Split(s, " ")
	seenScopes := map[string]bool{}
	dedupedScopes := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		if !slices.Contains(allowedScopes, scope) {
			return nil, errUnknownOrMalformedScope
		}

		if !seenScopes[scope] {
			seenScopes[scope] = true
			dedupedScopes = append(dedupedScopes, scope)
		}
	}

	return dedupedScopes, nil
}
