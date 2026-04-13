# Multi-Issuer HTTP Example with Redis Cache

This example demonstrates how to use the JWT middleware with multiple issuers (multi-tenant) using a Redis-backed cache for JWKS.

## Why Use Redis Cache?

**IMPORTANT**: For applications with **100+ tenants/issuers**, it is strongly recommended to use a custom cache implementation like Redis instead of the default in-memory cache.

### Benefits of Redis Cache:

1. **Memory Efficiency**: The default in-memory cache creates a separate cached JWKS entry per issuer, which can consume significant memory with many tenants
2. **Scalability**: Redis allows you to scale to hundreds or thousands of tenants without memory concerns
3. **Shared Cache**: Multiple application instances can share the same Redis cache, reducing redundant JWKS fetches
4. **Better Performance**: Avoids memory pressure and potential GC issues in high-tenant scenarios

## Prerequisites

- Go 1.23 or later
- Redis server running on `localhost:6379` (or modify the connection string in the code)

## Running Redis

If you don't have Redis installed, you can run it with Docker:

```bash
docker run -d --name redis -p 6379:6379 redis:latest
```

Or install Redis locally:
- macOS: `brew install redis && brew services start redis`
- Ubuntu: `sudo apt-get install redis-server && sudo systemctl start redis`

## Running the Example

1. Start Redis server (see above)

2. Run the example:
```bash
go run main.go
```

3. The server will start on `http://localhost:3000`

## Configuration

Update the following in `main.go`:

```go
issuers := []string{
    "https://tenant1.auth0.com/",
    "https://tenant2.auth0.com/",
    // Add as many issuers as needed - Redis handles the memory management
}

audience := []string{"<your api identifier>"}
```

## How It Works

1. The `RedisCache` struct implements the `jwks.Cache` interface
2. When a JWT is validated:
   - The middleware extracts the issuer from the token
   - The `MultiIssuerProvider` routes the request to the correct issuer
   - The Redis cache checks if JWKS is cached for that issuer
   - If not cached, it fetches from the OIDC provider and caches in Redis
3. Subsequent requests for the same issuer use the cached JWKS from Redis

## Cache TTL

The example uses a 15-minute TTL for cached JWKS:

```go
redisCache, err := NewRedisCache("localhost:6379", 15*time.Minute, nil)
```

Adjust this based on your security requirements and how frequently your JWKS keys rotate.

## Production Considerations

For production deployments:

1. **Redis Configuration**: Use a production-ready Redis setup with:
   - Authentication (`redis.Options{Password: "your-password"}`)
   - SSL/TLS if connecting to remote Redis
   - Redis Cluster for high availability

2. **Error Handling**: The example includes basic error handling. Consider adding:
   - Circuit breakers for Redis connection failures
   - Fallback to in-memory cache if Redis is unavailable
   - Metrics and monitoring

3. **Connection Pooling**: The go-redis client handles connection pooling automatically. Configure pool size based on your load:
   ```go
   client := redis.NewClient(&redis.Options{
       Addr:         "localhost:6379",
       PoolSize:     100,
       MinIdleConns: 10,
   })
   ```

4. **Key Naming**: Consider prefixing Redis keys to avoid collisions:
   ```go
   cacheKey := fmt.Sprintf("jwks:%s", jwksURI)
   ```

## Testing

You can test with any valid JWT from your configured issuers:

```bash
curl -H "Authorization: Bearer <your-jwt-token>" http://localhost:3000
```

The response will show which issuer validated the token:

```json
{
  "issuer": "https://tenant1.auth0.com/",
  "subject": "auth0|123456",
  "claims": { ... }
}
```
