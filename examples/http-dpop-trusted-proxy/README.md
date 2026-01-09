# DPoP with Trusted Proxy Example

This example demonstrates using the go-jwt-middleware with DPoP (Demonstrating Proof-of-Possession) support behind a reverse proxy.

## Overview

When your application is deployed behind a reverse proxy (Nginx, Apache, HAProxy, API Gateway), the middleware needs to reconstruct the original client request URL for DPoP HTU (HTTP URI) validation. This is done by trusting specific forwarded headers.

**SECURITY WARNING:** Only enable trusted proxies when your application is behind a reverse proxy that **strips** client-provided forwarded headers. DO NOT use this for direct internet-facing deployments.

## Trusted Proxy Configuration

The middleware provides four configuration options:

### 1. WithStandardProxy() - For Nginx, Apache, HAProxy
Trusts `X-Forwarded-Proto` and `X-Forwarded-Host` headers.

```go
middleware, err := jwtmiddleware.New(
    jwtmiddleware.WithValidator(jwtValidator),
    jwtmiddleware.WithStandardProxy(),
)
```

### 2. WithAPIGatewayProxy() - For API Gateways
Trusts `X-Forwarded-Proto`, `X-Forwarded-Host`, and `X-Forwarded-Prefix` headers.

```go
middleware, err := jwtmiddleware.New(
    jwtmiddleware.WithValidator(jwtValidator),
    jwtmiddleware.WithAPIGatewayProxy(),
)
```

### 3. WithRFC7239Proxy() - For RFC 7239 Forwarded Header
Trusts the structured `Forwarded` header (most secure option).

```go
middleware, err := jwtmiddleware.New(
    jwtmiddleware.WithValidator(jwtValidator),
    jwtmiddleware.WithRFC7239Proxy(),
)
```

### 4. WithTrustedProxies() - Custom Configuration
Granular control over which headers to trust.

```go
middleware, err := jwtmiddleware.New(
    jwtmiddleware.WithValidator(jwtValidator),
    jwtmiddleware.WithTrustedProxies(&jwtmiddleware.TrustedProxyConfig{
        TrustXForwardedProto:  true,
        TrustXForwardedHost:   true,
        TrustXForwardedPrefix: false,
        TrustForwarded:        false,
    }),
)
```

## Why This Matters for DPoP

DPoP proof validation requires matching the `htu` (HTTP URI) claim in the DPoP proof against the actual request URL. When behind a proxy:

```
Client Request:       https://api.example.com/api/v1/users
         ↓
Reverse Proxy:        Forwards to http://backend:3000/users
                      Adds: X-Forwarded-Proto: https
                      Adds: X-Forwarded-Host: api.example.com
                      Adds: X-Forwarded-Prefix: /api/v1
         ↓
App Server:           Reconstructs: https://api.example.com/api/v1/users
                      Validates DPoP proof HTU against this URL
```

Without trusted proxy configuration, the middleware would see `http://backend:3000/users` and reject valid DPoP proofs.

## Running the Example

```bash
go run main.go
```

## Testing

### Test with X-Forwarded Headers

```bash
curl -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiYXVkaWVuY2UtZXhhbXBsZSJdLCJleHAiOjIwNTMwNzA0MDAsImlhdCI6MTczNzcxMDQwMCwiaXNzIjoiZ28tand0LW1pZGRsZXdhcmUtZHBvcC1wcm94eS1leGFtcGxlIiwibmFtZSI6IkpvaG4gRG9lIiwic3ViIjoidXNlcjEyMyIsInVzZXJuYW1lIjoiam9obmRvZSJ9.67hi9dpfCzcRagv6GFkuaURBH3v7T6ya6k0nw_tYPW4' \
     -H 'X-Forwarded-Proto: https' \
     -H 'X-Forwarded-Host: api.example.com' \
     http://localhost:3000/users
```

### Test with RFC 7239 Forwarded Header

```bash
curl -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiYXVkaWVuY2UtZXhhbXBsZSJdLCJleHAiOjIwNTMwNzA0MDAsImlhdCI6MTczNzcxMDQwMCwiaXNzIjoiZ28tand0LW1pZGRsZXdhcmUtZHBvcC1wcm94eS1leGFtcGxlIiwibmFtZSI6IkpvaG4gRG9lIiwic3ViIjoidXNlcjEyMyIsInVzZXJuYW1lIjoiam9obmRvZSJ9.67hi9dpfCzcRagv6GFkuaURBH3v7T6ya6k0nw_tYPW4' \
     -H 'Forwarded: proto=https;host=api.example.com' \
     http://localhost:3000/users
```

### Test with Multiple Proxies

```bash
curl -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiYXVkaWVuY2UtZXhhbXBsZSJdLCJleHAiOjIwNTMwNzA0MDAsImlhdCI6MTczNzcxMDQwMCwiaXNzIjoiZ28tand0LW1pZGRsZXdhcmUtZHBvcC1wcm94eS1leGFtcGxlIiwibmFtZSI6IkpvaG4gRG9lIiwic3ViIjoidXNlcjEyMyIsInVzZXJuYW1lIjoiam9obmRvZSJ9.67hi9dpfCzcRagv6GFkuaURBH3v7T6ya6k0nw_tYPW4' \
     -H 'X-Forwarded-Proto: https, http, http' \
     -H 'X-Forwarded-Host: client.example.com, proxy1.internal, proxy2.internal' \
     http://localhost:3000/users
```

The middleware uses the **leftmost** value (closest to client):
- Proto: `https`
- Host: `client.example.com`

## Security Best Practices

1. **ONLY** enable trusted proxies when behind a reverse proxy
2. Ensure your reverse proxy **strips** client-provided forwarded headers
3. Use RFC 7239 `Forwarded` header if your proxy supports it (most secure)
4. Trust only the headers your proxy actually sets
5. For direct internet-facing apps, **DO NOT** configure trusted proxies

## Default Behavior (No Proxy Config)

If you don't configure trusted proxies (don't use any of the `With*Proxy()` options), the middleware ignores **ALL** forwarded headers and uses the direct request URL. This is the **secure default** for internet-facing applications.

## Response Format

The handler returns JSON with request information:

```json
{
  "subject": "user123",
  "username": "johndoe",
  "name": "John Doe",
  "issuer": "go-jwt-middleware-dpop-proxy-example",
  "request_url": "/users",
  "request_host": "localhost:3000",
  "request_proto": "HTTP/1.1",
  "proxy_headers": {
    "X-Forwarded-Proto": "https",
    "X-Forwarded-Host": "api.example.com"
  },
  "dpop_enabled": false,
  "token_type": "Bearer"
}
```

## See Also

- [http-dpop-example](../http-dpop-example) - Basic DPoP example without proxy configuration
- [http-dpop-required](../http-dpop-required) - DPoP required mode example
- [http-dpop-disabled](../http-dpop-disabled) - DPoP disabled mode example
