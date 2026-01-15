# Dynamic Issuer Resolution Example

This example demonstrates how to dynamically determine allowed issuers at request time based on request context (tenant ID, subdomain, etc.) with user-managed caching.

## Use Cases

- **Multi-tenant SaaS**: Resolve issuers based on tenant from request context
- **Database-backed configuration**: Store issuer lists in database, not code
- **Dynamic tenant onboarding**: Add new tenants without restarting the application
- **Per-tenant migration**: Support migration from old to new domains on a per-tenant basis

## How It Works

This example uses `WithIssuersResolver` to determine allowed issuers dynamically:

```go
issuerResolver := func(ctx context.Context) ([]string, error) {
    // Extract tenant ID from context
    tenantID, _ := ctx.Value(tenantContextKey{}).(string)

    // Check cache first (fast path)
    if cachedIssuers, found := cache.get(tenantID); found {
        return cachedIssuers, nil
    }

    // Cache miss - query database (slow path)
    issuers, _ := database.GetIssuers(tenantID)
    cache.set(tenantID, issuers) // Cache for next request

    return issuers, nil
}

jwtValidator, _ := validator.New(
    validator.WithKeyFunc(provider.KeyFunc),
    validator.WithAlgorithm(validator.RS256),
    validator.WithIssuersResolver(issuerResolver), // Dynamic!
    validator.WithAudiences(audience),
)
```

## Architecture

```
Request with X-Tenant-ID header
    ↓
1. tenantMiddleware extracts tenant → adds to context
    ↓
2. JWT middleware validates token
    ↓
3. issuerResolver called with context
   • Check in-memory cache (< 1ms)
   • If miss, query database (~10ms)
   • Cache result for 5 minutes
    ↓
4. MultiIssuerProvider routes JWKS request to validated issuer
    ↓
5. Token validated and request proceeds
```

## Key Features

- **User-Managed Caching**: You control the caching strategy (in-memory, Redis, etc.)
- **Context-Based Resolution**: Access request data (headers, path, etc.) in resolver
- **Performance**: Cache hits are < 1ms, cache misses still fast with database query
- **Flexible**: Easy to adapt to your specific requirements

## Running the Example

1. Update the audience in `main.go`:
   ```go
   mainHandler := setupHandler([]string{"your-api-identifier"})
   ```

2. The example includes a mock database with three configured tenants:
   - `tenant1`: Single issuer
   - `tenant2`: Single issuer
   - `tenant3`: Multiple issuers (migration scenario)

3. Run the server:
   ```bash
   go run main.go
   ```

4. Test with different tenants:
   ```bash
   # Test with tenant1
   curl -H "X-Tenant-ID: tenant1" \
        -H "Authorization: Bearer YOUR_TENANT1_JWT" \
        http://localhost:3000

   # Test with tenant2
   curl -H "X-Tenant-ID: tenant2" \
        -H "Authorization: Bearer YOUR_TENANT2_JWT" \
        http://localhost:3000
   ```

## Caching Behavior

Watch the console output to see caching in action:

```
[Cache MISS] Querying database for tenant tenant1
[Database] Tenant tenant1: [https://tenant1.auth0.com/] (cached for 5m)
[Cache HIT] Tenant tenant1: [https://tenant1.auth0.com/]
[Cache HIT] Tenant tenant1: [https://tenant1.auth0.com/]
```

First request is a cache miss (~10ms), subsequent requests are cache hits (< 1ms).

## Adapting to Your Environment

### Using Redis for Caching

```go
import "github.com/redis/go-redis/v9"

func createRedisCache(redisClient *redis.Client) issuerCache {
    return &redisCache{
        client: redisClient,
        ttl:    5 * time.Minute,
    }
}

func (c *redisCache) get(tenantID string) ([]string, bool) {
    result, err := c.client.Get(ctx, "issuers:"+tenantID).Result()
    if err != nil {
        return nil, false
    }
    return parseIssuers(result), true
}
```

### Extracting Tenant from Subdomain

```go
func tenantMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Extract tenant from subdomain: tenant1.api.example.com
        host := r.Host
        parts := strings.Split(host, ".")
        if len(parts) < 3 {
            http.Error(w, "Invalid host", http.StatusBadRequest)
            return
        }
        tenantID := parts[0]

        ctx := context.WithValue(r.Context(), tenantContextKey{}, tenantID)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}
```

### Using PostgreSQL

```go
import "database/sql"

func getTenantIssuersFromDB(ctx context.Context, tenantID string) ([]string, error) {
    query := `SELECT issuer_url FROM tenant_issuers WHERE tenant_id = $1 AND active = true`
    rows, err := db.QueryContext(ctx, query, tenantID)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var issuers []string
    for rows.Next() {
        var issuer string
        if err := rows.Scan(&issuer); err != nil {
            return nil, err
        }
        issuers = append(issuers, issuer)
    }

    return issuers, nil
}
```

## Performance Recommendations

- **Cache TTL**: 5-15 minutes is recommended for most use cases
- **Resolver Latency**: Target < 5ms (< 1ms with cache hit, < 20ms with database query)
- **Database**: Use connection pooling and prepare statements
- **Monitoring**: Track cache hit rate and resolver latency

## For Static Issuer Lists

If your issuers don't change at runtime, use the simpler [multi-issuer-example](../http-multi-issuer-example/) instead.
