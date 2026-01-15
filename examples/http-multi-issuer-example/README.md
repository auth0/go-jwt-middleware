# Multi-Issuer JWT Validation Example

This example demonstrates how to validate JWTs from multiple issuers (tenants) using a static list of allowed issuers.

## Use Cases

- Multi-tenant SaaS applications accepting tokens from multiple customer tenants
- Domain migrations supporting both old and new domains simultaneously
- Enterprise deployments handling multiple Auth0 tenants in a single API

## How It Works

This example uses the `MultiIssuerProvider` with a static list of allowed issuers:

```go
issuers := []string{
    "https://tenant1.auth0.com/",
    "https://tenant2.auth0.com/",
    "https://tenant3.auth0.com/",
}

provider, _ := jwks.NewMultiIssuerProvider(
    jwks.WithMultiIssuerCacheTTL(5*time.Minute),
)

jwtValidator, _ := validator.New(
    validator.WithKeyFunc(provider.KeyFunc),
    validator.WithAlgorithm(validator.RS256),
    validator.WithIssuers(issuers), // Multiple issuers
    validator.WithAudiences(audience),
)
```

## Key Features

- **Automatic JWKS Routing**: The `MultiIssuerProvider` automatically routes JWKS requests to the correct issuer
- **Security**: Issuer is validated BEFORE fetching JWKS (prevents SSRF attacks)
- **Performance**: Per-issuer JWKS caching with configurable TTL
- **Thread-Safe**: Safe for concurrent requests

## Running the Example

1. Update the issuer URLs and audience in `main.go`:
   ```go
   issuers := []string{
       "https://your-tenant1.auth0.com/",
       "https://your-tenant2.auth0.com/",
   }
   mainHandler := setupHandler(issuers, []string{"your-api-identifier"})
   ```

2. Run the server:
   ```bash
   go run main.go
   ```

3. Test with a JWT from any configured issuer:
   ```bash
   curl -H "Authorization: Bearer YOUR_JWT_TOKEN" http://localhost:3000
   ```

## Response Format

The API returns the validated claims including which issuer authenticated the token:

```json
{
  "issuer": "https://tenant1.auth0.com/",
  "subject": "auth0|123456",
  "claims": {
    "RegisteredClaims": {
      "Issuer": "https://tenant1.auth0.com/",
      "Subject": "auth0|123456",
      "Audience": ["your-api-identifier"]
    }
  }
}
```

## For Dynamic Issuer Resolution

If you need to determine issuers at runtime based on request context (e.g., from a database or tenant header), see the [dynamic-issuer-example](../http-dynamic-issuer-example/).
