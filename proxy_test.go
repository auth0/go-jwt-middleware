package jwtmiddleware

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReconstructRequestURL(t *testing.T) {
	t.Run("no proxy config - uses request URL directly", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://backend:8080/api/resource?page=1", nil)

		url := reconstructRequestURL(req, nil)

		assert.Equal(t, "http://backend:8080/api/resource?page=1", url)
	})

	t.Run("proxy config with all flags false - uses request URL directly", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://backend:8080/api/resource", nil)
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", "api.example.com")

		config := &TrustedProxyConfig{
			TrustXForwardedProto: false,
			TrustXForwardedHost:  false,
		}

		url := reconstructRequestURL(req, config)

		// Should ignore headers when config disables trust
		assert.Equal(t, "http://backend:8080/api/resource", url)
	})

	t.Run("trust X-Forwarded-Proto only", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://backend:8080/api/resource", nil)
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", "api.example.com")

		config := &TrustedProxyConfig{
			TrustXForwardedProto: true,
			TrustXForwardedHost:  false,
		}

		url := reconstructRequestURL(req, config)

		assert.Equal(t, "https://backend:8080/api/resource", url)
	})

	t.Run("trust X-Forwarded-Host only", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://backend:8080/api/resource", nil)
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", "api.example.com")

		config := &TrustedProxyConfig{
			TrustXForwardedProto: false,
			TrustXForwardedHost:  true,
		}

		url := reconstructRequestURL(req, config)

		assert.Equal(t, "http://api.example.com/api/resource", url)
	})

	t.Run("trust both X-Forwarded-Proto and X-Forwarded-Host", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://backend:8080/api/resource", nil)
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", "api.example.com")

		config := &TrustedProxyConfig{
			TrustXForwardedProto: true,
			TrustXForwardedHost:  true,
		}

		url := reconstructRequestURL(req, config)

		assert.Equal(t, "https://api.example.com/api/resource", url)
	})

	t.Run("trust X-Forwarded-Prefix", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://backend:8080/resource", nil)
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", "api.example.com")
		req.Header.Set("X-Forwarded-Prefix", "/api/v1")

		config := &TrustedProxyConfig{
			TrustXForwardedProto:  true,
			TrustXForwardedHost:   true,
			TrustXForwardedPrefix: true,
		}

		url := reconstructRequestURL(req, config)

		assert.Equal(t, "https://api.example.com/api/v1/resource", url)
	})

	t.Run("prefix without leading slash", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://backend:8080/resource", nil)
		req.Header.Set("X-Forwarded-Prefix", "api/v1")

		config := &TrustedProxyConfig{
			TrustXForwardedPrefix: true,
		}

		url := reconstructRequestURL(req, config)

		assert.Equal(t, "http://backend:8080/api/v1/resource", url)
	})

	t.Run("prefix with trailing slash", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://backend:8080/resource", nil)
		req.Header.Set("X-Forwarded-Prefix", "/api/v1/")

		config := &TrustedProxyConfig{
			TrustXForwardedPrefix: true,
		}

		url := reconstructRequestURL(req, config)

		assert.Equal(t, "http://backend:8080/api/v1/resource", url)
	})

	t.Run("multiple proxies - takes leftmost value", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://backend:8080/resource", nil)
		req.Header.Set("X-Forwarded-Proto", "https, https, http")
		req.Header.Set("X-Forwarded-Host", "api.example.com, proxy1.internal, proxy2.internal")

		config := &TrustedProxyConfig{
			TrustXForwardedProto: true,
			TrustXForwardedHost:  true,
		}

		url := reconstructRequestURL(req, config)

		assert.Equal(t, "https://api.example.com/resource", url)
	})

	t.Run("with query string", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://backend:8080/resource?page=1&limit=10", nil)
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", "api.example.com")

		config := &TrustedProxyConfig{
			TrustXForwardedProto: true,
			TrustXForwardedHost:  true,
		}

		url := reconstructRequestURL(req, config)

		assert.Equal(t, "https://api.example.com/resource?page=1&limit=10", url)
	})

	t.Run("RFC 7239 Forwarded header - proto and host", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://backend:8080/resource", nil)
		req.Header.Set("Forwarded", "for=192.0.2.60;proto=https;host=api.example.com")

		config := &TrustedProxyConfig{
			TrustForwarded: true,
		}

		url := reconstructRequestURL(req, config)

		assert.Equal(t, "https://api.example.com/resource", url)
	})

	t.Run("RFC 7239 Forwarded header - proto only", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://backend:8080/resource", nil)
		req.Header.Set("Forwarded", "proto=https")

		config := &TrustedProxyConfig{
			TrustForwarded: true,
		}

		url := reconstructRequestURL(req, config)

		assert.Equal(t, "https://backend:8080/resource", url)
	})

	t.Run("RFC 7239 Forwarded header - host only", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://backend:8080/resource", nil)
		req.Header.Set("Forwarded", "host=api.example.com")

		config := &TrustedProxyConfig{
			TrustForwarded: true,
		}

		url := reconstructRequestURL(req, config)

		assert.Equal(t, "http://api.example.com/resource", url)
	})

	t.Run("RFC 7239 Forwarded header - multiple entries takes leftmost", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://backend:8080/resource", nil)
		req.Header.Set("Forwarded", "proto=https;host=api.example.com, proto=http;host=proxy.internal")

		config := &TrustedProxyConfig{
			TrustForwarded: true,
		}

		url := reconstructRequestURL(req, config)

		assert.Equal(t, "https://api.example.com/resource", url)
	})

	t.Run("RFC 7239 takes precedence over X-Forwarded", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://backend:8080/resource", nil)
		req.Header.Set("Forwarded", "proto=https;host=api.example.com")
		req.Header.Set("X-Forwarded-Proto", "http")
		req.Header.Set("X-Forwarded-Host", "wrong.example.com")

		config := &TrustedProxyConfig{
			TrustForwarded:       true,
			TrustXForwardedProto: true,
			TrustXForwardedHost:  true,
		}

		url := reconstructRequestURL(req, config)

		// Forwarded header should take precedence
		assert.Equal(t, "https://api.example.com/resource", url)
	})

	t.Run("HTTPS request without headers", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://backend:8443/resource", nil)
		req.TLS = &tls.ConnectionState{}

		url := reconstructRequestURL(req, nil)

		assert.Equal(t, "https://backend:8443/resource", url)
	})
}

func TestGetLeftmost(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "single value",
			input:    "value1",
			expected: "value1",
		},
		{
			name:     "multiple values",
			input:    "value1, value2, value3",
			expected: "value1",
		},
		{
			name:     "multiple values with spaces",
			input:    "  value1  ,  value2  ",
			expected: "value1",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getLeftmost(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}

	// Note: The `if len(parts) == 0` check in getLeftmost is defensive code
	// that cannot be reached in practice, since strings.Split() always returns
	// at least one element (even for empty strings). This is kept for defensive
	// programming and clear intent.
}

func TestParseForwardedHeader(t *testing.T) {
	tests := []struct {
		name           string
		forwarded      string
		expectedScheme string
		expectedHost   string
	}{
		{
			name:           "proto and host",
			forwarded:      "proto=https;host=api.example.com",
			expectedScheme: "https",
			expectedHost:   "api.example.com",
		},
		{
			name:           "proto only",
			forwarded:      "proto=https",
			expectedScheme: "https",
			expectedHost:   "",
		},
		{
			name:           "host only",
			forwarded:      "host=api.example.com",
			expectedScheme: "",
			expectedHost:   "api.example.com",
		},
		{
			name:           "with for parameter",
			forwarded:      "for=192.0.2.60;proto=https;host=api.example.com",
			expectedScheme: "https",
			expectedHost:   "api.example.com",
		},
		{
			name:           "quoted values",
			forwarded:      `proto="https";host="api.example.com"`,
			expectedScheme: "https",
			expectedHost:   "api.example.com",
		},
		{
			name:           "multiple entries - takes leftmost",
			forwarded:      "proto=https;host=api.example.com, proto=http;host=proxy.internal",
			expectedScheme: "https",
			expectedHost:   "api.example.com",
		},
		{
			name:           "empty string",
			forwarded:      "",
			expectedScheme: "",
			expectedHost:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme, host := parseForwardedHeader(tt.forwarded)
			assert.Equal(t, tt.expectedScheme, scheme)
			assert.Equal(t, tt.expectedHost, host)
		})
	}

	// Note: The `if len(entries) == 0` check in parseForwardedHeader is defensive code
	// that cannot be reached in practice, since strings.Split() always returns
	// at least one element (even for empty strings). This is kept for defensive
	// programming and clear intent.
}

func TestTrustedProxyConfigHasAnyTrustedHeaders(t *testing.T) {
	t.Run("nil config", func(t *testing.T) {
		var config *TrustedProxyConfig
		assert.False(t, config.hasAnyTrustedHeaders())
	})

	t.Run("all false", func(t *testing.T) {
		config := &TrustedProxyConfig{}
		assert.False(t, config.hasAnyTrustedHeaders())
	})

	t.Run("TrustXForwardedProto true", func(t *testing.T) {
		config := &TrustedProxyConfig{
			TrustXForwardedProto: true,
		}
		assert.True(t, config.hasAnyTrustedHeaders())
	})

	t.Run("TrustXForwardedHost true", func(t *testing.T) {
		config := &TrustedProxyConfig{
			TrustXForwardedHost: true,
		}
		assert.True(t, config.hasAnyTrustedHeaders())
	})

	t.Run("TrustXForwardedPrefix true", func(t *testing.T) {
		config := &TrustedProxyConfig{
			TrustXForwardedPrefix: true,
		}
		assert.True(t, config.hasAnyTrustedHeaders())
	})

	t.Run("TrustForwarded true", func(t *testing.T) {
		config := &TrustedProxyConfig{
			TrustForwarded: true,
		}
		assert.True(t, config.hasAnyTrustedHeaders())
	})
}

func TestNormalizePort(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		scheme   string
		expected string
	}{
		// Standard cases (already covered)
		{
			name:     "HTTP with default port 80",
			host:     "example.com:80",
			scheme:   "http",
			expected: "example.com",
		},
		{
			name:     "HTTPS with default port 443",
			host:     "example.com:443",
			scheme:   "https",
			expected: "example.com",
		},
		{
			name:     "HTTP with non-default port",
			host:     "example.com:8080",
			scheme:   "http",
			expected: "example.com:8080",
		},
		{
			name:     "HTTPS with non-default port",
			host:     "example.com:8443",
			scheme:   "https",
			expected: "example.com:8443",
		},
		{
			name:     "no port specified",
			host:     "example.com",
			scheme:   "https",
			expected: "example.com",
		},
		// IPv6 cases (needed for better coverage)
		{
			name:     "IPv6 with default HTTP port",
			host:     "[::1]:80",
			scheme:   "http",
			expected: "[::1]",
		},
		{
			name:     "IPv6 with default HTTPS port",
			host:     "[::1]:443",
			scheme:   "https",
			expected: "[::1]",
		},
		{
			name:     "IPv6 with non-default port",
			host:     "[::1]:8080",
			scheme:   "http",
			expected: "[::1]:8080",
		},
		{
			name:     "IPv6 without port",
			host:     "[::1]",
			scheme:   "https",
			expected: "[::1]",
		},
		{
			name:     "IPv6 full address with default port",
			host:     "[2001:db8::1]:443",
			scheme:   "https",
			expected: "[2001:db8::1]",
		},
		{
			name:     "IPv6 full address with custom port",
			host:     "[2001:db8::1]:8443",
			scheme:   "https",
			expected: "[2001:db8::1]:8443",
		},
		// Edge cases for defensive code paths
		{
			name:     "IPv6 malformed - no closing bracket",
			host:     "[::1:8080",
			scheme:   "http",
			expected: "[::1:8080", // Returns as-is since malformed
		},
		{
			name:     "IPv6 with colon before bracket",
			host:     "[::1]",
			scheme:   "http",
			expected: "[::1]", // No port, returns as-is
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizePort(tt.host, tt.scheme)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestProxyConfigurationOptions(t *testing.T) {
	t.Run("WithStandardProxy", func(t *testing.T) {
		m := &JWTMiddleware{}
		opt := WithStandardProxy()

		err := opt(m)

		assert.NoError(t, err)
		assert.NotNil(t, m.trustedProxies)
		assert.True(t, m.trustedProxies.TrustXForwardedProto)
		assert.True(t, m.trustedProxies.TrustXForwardedHost)
		assert.False(t, m.trustedProxies.TrustXForwardedPrefix)
		assert.False(t, m.trustedProxies.TrustForwarded)
	})

	t.Run("WithAPIGatewayProxy", func(t *testing.T) {
		m := &JWTMiddleware{}
		opt := WithAPIGatewayProxy()

		err := opt(m)

		assert.NoError(t, err)
		assert.NotNil(t, m.trustedProxies)
		assert.True(t, m.trustedProxies.TrustXForwardedProto)
		assert.True(t, m.trustedProxies.TrustXForwardedHost)
		assert.True(t, m.trustedProxies.TrustXForwardedPrefix)
		assert.False(t, m.trustedProxies.TrustForwarded)
	})

	t.Run("WithRFC7239Proxy", func(t *testing.T) {
		m := &JWTMiddleware{}
		opt := WithRFC7239Proxy()

		err := opt(m)

		assert.NoError(t, err)
		assert.NotNil(t, m.trustedProxies)
		assert.False(t, m.trustedProxies.TrustXForwardedProto)
		assert.False(t, m.trustedProxies.TrustXForwardedHost)
		assert.False(t, m.trustedProxies.TrustXForwardedPrefix)
		assert.True(t, m.trustedProxies.TrustForwarded)
	})

	t.Run("WithTrustedProxies nil", func(t *testing.T) {
		m := &JWTMiddleware{}
		opt := WithTrustedProxies(nil)

		err := opt(m)

		assert.NoError(t, err)
		assert.Nil(t, m.trustedProxies)
	})

	t.Run("WithTrustedProxies custom", func(t *testing.T) {
		m := &JWTMiddleware{}
		customConfig := &TrustedProxyConfig{
			TrustXForwardedProto: true,
			TrustForwarded:       true,
		}
		opt := WithTrustedProxies(customConfig)

		err := opt(m)

		assert.NoError(t, err)
		assert.Equal(t, customConfig, m.trustedProxies)
	})
}
