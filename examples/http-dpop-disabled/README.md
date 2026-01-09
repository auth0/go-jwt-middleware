# DPoP Disabled Mode Example

This example demonstrates the **DPoP Disabled** mode, which explicitly opts out of DPoP support.

> **Note**: For other DPoP modes, see:
> - [http-dpop-example](../http-dpop-example/) - DPoP Allowed mode (default - accepts both Bearer and DPoP)
> - [http-dpop-required](../http-dpop-required/) - DPoP Required mode (only DPoP tokens)

## What is DPoP Disabled Mode?

In DPoP Disabled mode, the server:
- ✅ **ONLY accepts Bearer tokens** (traditional OAuth 2.0)
- ⚠️ **Ignores DPoP headers** completely
- ❌ **Rejects DPoP scheme** in Authorization header

This mode is ideal for:
- 📦 **Legacy systems** that don't support DPoP
- 🔧 **Explicit opt-out** when you don't want DPoP
- 🎯 **Simple deployments** without DPoP complexity
- 🔄 **Rollback scenarios** if issues arise

## Running the Example

```bash
go run main.go
```

The server will start on `http://localhost:3002`

## Testing with Bearer Tokens (Success)

Use a regular Bearer token:

```bash
curl -H "Authorization: Bearer <your-bearer-token>" \
     http://localhost:3002/
```

**Expected Response:**
```json
{
  "message": "DPoP Disabled Mode - Only Bearer tokens accepted",
  "subject": "user123",
  "token_type": "Bearer",
  ...
}
```

## Testing with DPoP Scheme (Rejection)

Try using DPoP in the Authorization header:

```bash
curl -v -H "Authorization: DPoP <your-dpop-token>" \
     -H "DPoP: <your-dpop-proof>" \
     http://localhost:3002/
```

**Expected Response:**
```
HTTP/1.1 400 Bad Request
WWW-Authenticate: Bearer realm="api"

{
  "error": "invalid_request",
  "error_description": "Invalid authentication scheme",
  "error_code": "invalid_scheme"
}
```

## Configuration

```go
middleware := jwtmiddleware.New(
    jwtmiddleware.WithValidator(jwtValidator),
    jwtmiddleware.WithDPoPMode(core.DPoPDisabled),
)
```

## Key Features

1. **Traditional OAuth 2.0**: Standard Bearer token authentication
2. **DPoP Headers Ignored**: Any DPoP headers are simply ignored
3. **Explicit Opt-Out**: Clear signal that DPoP is not supported
4. **Backward Compatible**: Works with all existing OAuth 2.0 clients

## Use Cases

- **Legacy Systems**: Applications that can't be updated
- **Simple APIs**: When DPoP complexity isn't needed
- **Temporary Rollback**: If DPoP causes issues, quickly disable it
- **Specific Routes**: Disable DPoP for certain endpoints
- **Testing**: Compare Bearer-only vs DPoP performance

## Comparison with Other Modes

| Feature | DPoP Allowed<br/>(http-dpop-example) | DPoP Required<br/>(http-dpop-required) | DPoP Disabled<br/>(this example) |
|---------|--------------|---------------|---------------|
| Bearer Tokens | ✅ Accepted | ❌ Rejected | ✅ Accepted |
| DPoP Tokens | ✅ Accepted | ✅ Accepted | ❌ Rejected |
| DPoP Headers | ✅ Validated | ✅ Validated | ⚠️ Ignored |
| Default Mode | ✅ Yes | ❌ No | ❌ No |

## When to Use This Mode

### ✅ Good Use Cases
- Legacy applications that can't be updated
- APIs with no sensitive data
- Development/testing environments
- Gradual rollout (specific endpoints only)

### ❌ Avoid When
- Building new APIs (use DPoP Allowed instead)
- Handling sensitive data
- Zero-trust architecture required
- Token theft is a concern

## Security Considerations

⚠️ **Warning**: Bearer tokens are vulnerable to:
- Token theft (if intercepted)
- Replay attacks
- Man-in-the-middle attacks (without HTTPS)

🔒 **Recommendations**:
- Always use HTTPS
- Keep token expiration short
- Monitor for suspicious activity
- Consider DPoP Allowed mode instead

## Migration Strategy

If you need to disable DPoP temporarily:

```go
// In emergency situations, quickly disable DPoP
middleware := jwtmiddleware.New(
    jwtmiddleware.WithValidator(jwtValidator),
    jwtmiddleware.WithDPoPMode(core.DPoPDisabled), // Quick rollback
)
```

Then investigate and fix issues before re-enabling:

```go
// After fixes, return to DPoP Allowed mode
middleware := jwtmiddleware.New(
    jwtmiddleware.WithValidator(jwtValidator),
    // DPoPAllowed is the default - supports both token types
)
```

## Error Responses

### DPoP Scheme Used
```json
{
  "error": "invalid_request",
  "error_description": "Invalid authentication scheme",
  "error_code": "invalid_scheme"
}
```

### Missing Authorization Header
```json
{
  "error": "invalid_token",
  "error_description": "JWT is missing",
  "error_code": "token_missing"
}
```
