package routing

import "strings"

// IsCatchAllPath reports whether prefix matches any request path (* or legacy empty).
func IsCatchAllPath(p string) bool {
	p = strings.TrimSpace(p)
	return p == "" || p == "*" || p == "/"
}

// NormalizePathPrefix returns a canonical path prefix ("*", "" catch-all, or "/foo" without trailing slash).
func NormalizePathPrefix(p string) string {
	p = strings.TrimSpace(p)
	if p == "*" {
		return "*"
	}
	if p == "" || p == "/" {
		return ""
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	p = strings.TrimSuffix(p, "/")
	if p == "" {
		return ""
	}
	return p
}

// RequestPath returns the path used for backend prefix matching.
func RequestPath(urlPath string) string {
	p := strings.TrimSpace(urlPath)
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		return "/" + p
	}
	return p
}

// PathMatchesPrefix reports whether reqPath is under prefix (prefix normalized).
func PathMatchesPrefix(reqPath, prefix string) bool {
	if IsCatchAllPath(prefix) {
		return true
	}
	prefix = NormalizePathPrefix(prefix)
	if prefix == "" || prefix == "*" {
		return true
	}
	reqPath = RequestPath(reqPath)
	if reqPath == prefix {
		return true
	}
	return strings.HasPrefix(reqPath, prefix+"/")
}

// StripPathPrefix removes a matched prefix from reqPath for upstream forwarding.
func StripPathPrefix(reqPath, prefix string) string {
	if IsCatchAllPath(prefix) {
		return RequestPath(reqPath)
	}
	prefix = NormalizePathPrefix(prefix)
	reqPath = RequestPath(reqPath)
	if prefix == "" || prefix == "*" {
		return reqPath
	}
	if reqPath == prefix {
		return "/"
	}
	if strings.HasPrefix(reqPath, prefix+"/") {
		rest := strings.TrimPrefix(reqPath, prefix)
		if rest == "" {
			return "/"
		}
		return rest
	}
	return reqPath
}
