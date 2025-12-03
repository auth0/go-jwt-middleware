package jwtmiddleware

import (
	"net/http"
	"strings"
)

// TrustedProxyConfig defines which reverse proxy headers to trust.
//
// SECURITY WARNING: Only enable when behind a trusted reverse proxy!
// Enabling this in direct internet-facing deployments allows header injection attacks.
//
// When enabled, the middleware will trust forwarded headers (X-Forwarded-*, Forwarded)
// to reconstruct the original client request URL for DPoP HTU validation.
//
// Design decisions and considerations:
// - Secure by default: nil config means NO headers are trusted
// - Explicit opt-in required for each header type
// - RFC 7239 Forwarded takes precedence over X-Forwarded-* when both are enabled
// - Leftmost value used for multi-proxy chains (closest to client)
// - Empty or malformed headers are safely ignored (falls back to direct request)
//
// Known limitations:
// - Headers are assumed to be properly sanitized by the reverse proxy
// - No validation of header value formats (relies on reverse proxy to provide valid values)
// - Port numbers are stripped from host for HTU validation (per DPoP spec)
//
// Future considerations:
// - Configurable header value length limits
// - Support for custom/non-standard forwarded headers
type TrustedProxyConfig struct {
	// TrustXForwardedProto enables X-Forwarded-Proto header (https/http scheme)
	TrustXForwardedProto bool

	// TrustXForwardedHost enables X-Forwarded-Host header (original hostname)
	TrustXForwardedHost bool

	// TrustXForwardedPrefix enables X-Forwarded-Prefix header (API gateway path prefix)
	TrustXForwardedPrefix bool

	// TrustForwarded enables RFC 7239 Forwarded header (most secure, structured format)
	TrustForwarded bool
}

// hasAnyTrustedHeaders returns true if any header trust flags are enabled
func (c *TrustedProxyConfig) hasAnyTrustedHeaders() bool {
	if c == nil {
		return false
	}
	return c.TrustXForwardedProto ||
		c.TrustXForwardedHost ||
		c.TrustXForwardedPrefix ||
		c.TrustForwarded
}

// WithTrustedProxies configures trusted proxy headers for URL reconstruction.
// Required when behind reverse proxies to correctly validate DPoP HTU claim.
//
// SECURITY WARNING: Only use when your application is behind a trusted reverse proxy
// that strips client-provided forwarded headers. DO NOT use for direct internet-facing deployments.
//
// Example:
//
//	middleware, err := jwtmiddleware.New(
//	    jwtmiddleware.WithValidator(validator),
//	    jwtmiddleware.WithTrustedProxies(&jwtmiddleware.TrustedProxyConfig{
//	        TrustXForwardedProto: true,
//	        TrustXForwardedHost:  true,
//	    }),
//	)
func WithTrustedProxies(config *TrustedProxyConfig) Option {
	return func(m *JWTMiddleware) error {
		if config == nil {
			return nil
		}
		m.trustedProxies = config
		return nil
	}
}

// WithStandardProxy configures trust for standard reverse proxies (Nginx, Apache, HAProxy).
// Trusts X-Forwarded-Proto and X-Forwarded-Host headers.
// Use this for typical web server deployments behind a reverse proxy.
//
// This is a convenience function equivalent to:
//
//	WithTrustedProxies(&TrustedProxyConfig{
//	    TrustXForwardedProto: true,
//	    TrustXForwardedHost:  true,
//	})
//
// Example:
//
//	middleware, err := jwtmiddleware.New(
//	    jwtmiddleware.WithValidator(validator),
//	    jwtmiddleware.WithStandardProxy(),
//	)
func WithStandardProxy() Option {
	return WithTrustedProxies(&TrustedProxyConfig{
		TrustXForwardedProto: true,
		TrustXForwardedHost:  true,
	})
}

// WithAPIGatewayProxy configures trust for API gateways (AWS API Gateway, Kong, Traefik).
// Trusts X-Forwarded-Proto, X-Forwarded-Host, and X-Forwarded-Prefix headers.
// Use this when your gateway adds path prefixes (e.g., /api/v1).
//
// This is a convenience function equivalent to:
//
//	WithTrustedProxies(&TrustedProxyConfig{
//	    TrustXForwardedProto:  true,
//	    TrustXForwardedHost:   true,
//	    TrustXForwardedPrefix: true,
//	})
//
// Example:
//
//	middleware, err := jwtmiddleware.New(
//	    jwtmiddleware.WithValidator(validator),
//	    jwtmiddleware.WithAPIGatewayProxy(),
//	)
func WithAPIGatewayProxy() Option {
	return WithTrustedProxies(&TrustedProxyConfig{
		TrustXForwardedProto:  true,
		TrustXForwardedHost:   true,
		TrustXForwardedPrefix: true,
	})
}

// WithRFC7239Proxy configures trust for RFC 7239 Forwarded header.
// This is the most secure option if your proxy supports the structured Forwarded header.
//
// This is a convenience function equivalent to:
//
//	WithTrustedProxies(&TrustedProxyConfig{
//	    TrustForwarded: true,
//	})
//
// Example:
//
//	middleware, err := jwtmiddleware.New(
//	    jwtmiddleware.WithValidator(validator),
//	    jwtmiddleware.WithRFC7239Proxy(),
//	)
func WithRFC7239Proxy() Option {
	return WithTrustedProxies(&TrustedProxyConfig{
		TrustForwarded: true,
	})
}

// reconstructRequestURL builds the full request URL for DPoP HTU validation.
// It respects the TrustedProxyConfig to determine which headers to trust.
//
// When no proxy config is set or all flags are false (secure default),
// it uses the request URL as-is without trusting any forwarded headers.
//
// Per RFC 9449 and RFC 3986 Section 6.2.3, default ports are normalized:
// - http://example.com:80/ → http://example.com/
// - https://example.com:443/ → https://example.com/
// - Non-standard ports are preserved: http://example.com:8080/ → http://example.com:8080/
func reconstructRequestURL(r *http.Request, config *TrustedProxyConfig) string {
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	host := r.Host
	path := r.URL.Path
	query := r.URL.RawQuery
	pathPrefix := ""

	// If no proxy config or all flags false, use request URL as-is (secure default)
	if config == nil || !config.hasAnyTrustedHeaders() {
		host = normalizePort(host, scheme)
		url := scheme + "://" + host + path
		if query != "" {
			url += "?" + query
		}
		return url
	}

	forwardedScheme := ""
	forwardedHost := ""

	// 1. Try RFC 7239 Forwarded header (most secure, takes precedence)
	if config.TrustForwarded {
		if forwarded := r.Header.Get("Forwarded"); forwarded != "" {
			forwardedScheme, forwardedHost = parseForwardedHeader(forwarded)
			if forwardedScheme != "" {
				scheme = forwardedScheme
			}
			if forwardedHost != "" {
				host = forwardedHost
			}
		}
	}

	// 2. Try X-Forwarded-* headers (most common) - only if Forwarded didn't provide values
	if config.TrustXForwardedProto && forwardedScheme == "" {
		if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
			scheme = getLeftmost(proto)
		}
	}

	if config.TrustXForwardedHost && forwardedHost == "" {
		if hostHeader := r.Header.Get("X-Forwarded-Host"); hostHeader != "" {
			host = getLeftmost(hostHeader)
		}
	}

	if config.TrustXForwardedPrefix {
		if prefix := r.Header.Get("X-Forwarded-Prefix"); prefix != "" {
			pathPrefix = getLeftmost(prefix)
			// Ensure prefix starts with / and doesn't end with /
			if !strings.HasPrefix(pathPrefix, "/") {
				pathPrefix = "/" + pathPrefix
			}
			pathPrefix = strings.TrimSuffix(pathPrefix, "/")
		}
	}

	// 3. Normalize port based on scheme (strip default ports)
	host = normalizePort(host, scheme)

	// 4. Build reconstructed URL with optional prefix
	fullPath := pathPrefix + path
	reconstructed := scheme + "://" + host + fullPath
	if query != "" {
		reconstructed += "?" + query
	}

	return reconstructed
}

// getLeftmost extracts the leftmost value from a comma-separated header.
// This handles multiple proxies: "value1, value2, value3" -> "value1"
// The leftmost value is closest to the client.
func getLeftmost(header string) string {
	parts := strings.Split(header, ",")
	if len(parts) == 0 {
		return ""
	}
	return strings.TrimSpace(parts[0])
}

// parseForwardedHeader parses RFC 7239 Forwarded header.
// Example: "for=192.0.2.60;proto=https;host=api.example.com"
// Returns extracted scheme and host.
func parseForwardedHeader(forwarded string) (scheme, host string) {
	// Handle multiple forwarded entries (leftmost is closest to client)
	entries := strings.Split(forwarded, ",")
	if len(entries) == 0 {
		return "", ""
	}

	// Parse the first (leftmost) entry
	entry := strings.TrimSpace(entries[0])
	parts := strings.Split(entry, ";")

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "proto=") {
			scheme = strings.TrimPrefix(part, "proto=")
			scheme = strings.Trim(scheme, `"`) // Remove quotes if present
		} else if strings.HasPrefix(part, "host=") {
			host = strings.TrimPrefix(part, "host=")
			host = strings.Trim(host, `"`) // Remove quotes if present
		}
	}

	return scheme, host
}

// normalizePort normalizes the host by stripping default ports per RFC 3986 Section 6.2.3.
// This is required for DPoP HTU validation to avoid false mismatches on semantically equivalent URLs.
//
// Examples:
//   - http://example.com:80 → http://example.com
//   - https://example.com:443 → https://example.com
//   - http://example.com:8080 → http://example.com:8080 (preserved)
func normalizePort(host, scheme string) string {
	// Split host and port
	colonIdx := strings.LastIndex(host, ":")
	if colonIdx == -1 {
		// No port specified
		return host
	}

	// Check for IPv6 addresses (contain brackets)
	if strings.Contains(host, "[") {
		// IPv6 address like [::1]:8080
		closeBracketIdx := strings.Index(host, "]")
		if closeBracketIdx == -1 || colonIdx < closeBracketIdx {
			// Malformed or no port after bracket
			return host
		}
		port := host[colonIdx+1:]
		hostPart := host[:colonIdx]

		// Strip default ports
		if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
			return hostPart
		}
		return host
	}

	// IPv4 or hostname
	port := host[colonIdx+1:]
	hostPart := host[:colonIdx]

	// Strip default ports
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		return hostPart
	}

	return host
}
