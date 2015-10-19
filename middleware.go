package cors

import (
	"fmt"
	"regexp"

	"net/http"
)

// host struct represents a single configuration for an origin.
type host struct {
	Methods []string
	Headers []string
}

// Middleware struct holds configuration parameters.
type Middleware struct {
	AllowedOrigins map[string]*host
}

// NewHandler initializes a new handler from the middleware config and adds it to the middleware chain.
func (m *Middleware) NewHandler(next http.Handler) (http.Handler, error) {
	return &Handler{next: next, cfg: *m}, nil
}

// String() will be called by loggers inside Vulcand and command line tool.
func (m *Middleware) String() string {
	return fmt.Sprintf("origins=%v", m.AllowedOrigins)
}

// Validates that the given origin is allowed.
func (m *Middleware) isOriginAllowed(origin string) bool {
	if origin == "" {
		return false
	} else if m.AllowedOrigins[allToken] != nil {
		return true
	} else if m.AllowedOrigins[origin] != nil {
		return true
	} else if m.originMatchesRegex(origin) {
		return true
	}

	return false
}

func (m *Middleware) originMatchesRegex(origin string) bool {
	re, err := regexp.Compile("^/(.+)/$")
	if err != nil {
		return false
	}

	for k, _ := range m.AllowedOrigins {
		if re.MatchString(k) {
			url := fmt.Sprintf("^%s$", re.FindStringSubmatch(k)[1])
			match, _ := regexp.MatchString(url, origin)

			if match {
				m.AllowedOrigins[origin] = m.AllowedOrigins[k]
				return true
			}
		}
	}

	return false
}

// Validates that the given method is allowed.
func (m *Middleware) isMethodAllowed(method string, origin string) bool {
	if method == "" {
		return false
	}

	if method == optionsMethod {
		return true
	}

	allowedOrigin := m.findOrigin(origin)
	if allowedOrigin == nil {
		return false
	}

	for _, m := range allowedOrigin.Methods {
		if m == allToken || m == method {
			return true
		}
	}

	return false
}

// Validates that ALL of the given headers are allowed.
func (m *Middleware) areHeadersAllowed(headers []string, origin string) bool {
	if len(headers) == 0 {
		return true
	}

	allowedOrigin := m.findOrigin(origin)
	if allowedOrigin == nil {
		return false
	}

	if stringInSlice(allToken, allowedOrigin.Headers) {
		return true
	}

	for _, h := range headers {
		h = http.CanonicalHeaderKey(h)
		if h != "" && !stringInSlice(h, allowedOrigin.Headers) {
			return false
		}
	}

	return true
}

// Looks for the given origin or "*" if present.
func (m *Middleware) findOrigin(origin string) *host {
	allowedOrigin := m.AllowedOrigins[origin]
	if allowedOrigin == nil {
		allowedOrigin = m.AllowedOrigins[allToken]
	}

	return allowedOrigin
}
