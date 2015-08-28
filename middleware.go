package cors

import (
	"fmt"

	"net/http"
)

// host struct represents a single configuration for an origin.
type host struct {
	Methods []string
	Headers []string
}

// Middleware struct holds configuration parameters.
type Middleware struct {
	allowedOrigins map[string]*host
}

// NewHandler initializes a new handler from the middleware config and adds it to the middleware chain.
func (m *Middleware) NewHandler(next http.Handler) (http.Handler, error) {
	return &Handler{next: next, cfg: *m}, nil
}

// String() will be called by loggers inside Vulcand and command line tool.
func (m *Middleware) String() string {
	return fmt.Sprintf("origins=%v", m.allowedOrigins)
}

// Validates that the given origin is allowed.
func (m *Middleware) isOriginAllowed(origin string) bool {
	if origin == "" {
		return false
	} else if m.allowedOrigins[allToken] != nil {
		return true
	} else if m.allowedOrigins[origin] != nil {
		return true
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
	allowedOrigin := m.allowedOrigins[origin]
	if allowedOrigin == nil {
		allowedOrigin = m.allowedOrigins[allToken]
	}

	return allowedOrigin
}
