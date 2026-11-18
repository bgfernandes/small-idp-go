// Package issuer implements the issuer identifier (RFC 8414 §2).
package issuer

import (
	"errors"
	"fmt"
	"net/url"
	"path"
	"strings"
)

// Issuer is a validated issuer identifier (RFC 8414 §2). The zero value is invalid.
type Issuer struct {
	u *url.URL
}

// Parse validates and returns an Issuer from a string.
func Parse(s string) (Issuer, error) {
	// Validate issuer per RFC 8414 §2, accepting plain HTTP for now
	issuerURL, err := url.Parse(s)
	if err != nil {
		return Issuer{}, fmt.Errorf("invalid issuer URL: %w", err)
	}
	if issuerURL.Scheme != "http" && issuerURL.Scheme != "https" {
		return Issuer{}, errors.New("issuer must use HTTP or HTTPS scheme")
	}
	if issuerURL.Host == "" {
		return Issuer{}, errors.New("issuer must have a host")
	}
	// Do not allow query params or fragments as per RFC 8414 §2
	if strings.ContainsAny(s, "?#") {
		return Issuer{}, errors.New("issuer must not have query params or fragments")
	}
	// Do not allow trailing slash for consistency
	if strings.HasSuffix(s, "/") {
		return Issuer{}, errors.New("issuer must not have a trailing slash")
	}

	return Issuer{u: issuerURL}, nil
}

// MustParse validates and returns an Issuer from a string and panics on error. It exists for
// initialising package-level variables.
func MustParse(s string) Issuer {
	i, err := Parse(s)
	if err != nil {
		panic(err)
	}
	return i
}

// IsZero returns true if the Issuer is zero value.
func (i Issuer) IsZero() bool {
	return i.u == nil
}

// String returns the string representation of the Issuer.
func (i Issuer) String() string {
	if i.IsZero() {
		return ""
	}
	return i.u.String()
}

// URL returns the URL representation of the Issuer with appended path elements.
// If the Issuer is zero value, an empty string is returned.
func (i Issuer) URL(elem ...string) string {
	if i.IsZero() {
		return ""
	}
	u := i.u.JoinPath(elem...)
	return u.String()
}

// Path returns the path with appended path elements and a leading slash.
// If the Issuer is zero value, an empty string is returned.
func (i Issuer) Path(elem ...string) string {
	if i.IsZero() {
		return ""
	}
	parts := append([]string{"/", i.u.EscapedPath()}, elem...)
	return path.Join(parts...)
}
