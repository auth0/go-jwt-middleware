# DPoP Required Mode Example

This example demonstrates the **DPoP Required** mode, which provides **maximum security**.

> **Note**: For DPoP Allowed mode (default - accepts both Bearer and DPoP tokens), see the [http-dpop-example](../http-dpop-example/) directory.

## What is DPoP Required Mode?

In DPoP Required mode, the server:
- ✅ **ONLY accepts DPoP tokens** (with proof validation)
- ❌ **REJECTS Bearer tokens** (returns 400 Bad Request with error)

This mode is ideal for:
- 🔒 **Maximum security** - all tokens are sender-constrained
- 🎯 **Zero-trust architecture** - proof of possession required
- 🚀 **Post-migration** - after all clients support DPoP
- 🛡️ **High-value APIs** - financial, healthcare, sensitive data

## Running the Example

```bash
go run main.go
```

The server will start on `http://localhost:3001`

## Testing with DPoP Tokens (Success)

Create a DPoP-bound token and proof:

```bash
curl -H "Authorization: DPoP <your-dpop-token>" \
     -H "DPoP: <your-dpop-proof>" \
     http://localhost:3001/
```

**Expected Response:**
```json
{
  "message": "DPoP Required Mode - Only DPoP tokens accepted",
  "subject": "user123",
  "token_type": "DPoP",
  "dpop_info": {
    "public_key_thumbprint": "abc123...",
    "issued_at": "2025-11-25T10:00:00Z"
  },
  ...
}
```

## Testing with Bearer Tokens (Rejection)

Try using a Bearer token:

```bash
curl -v -H "Authorization: Bearer <your-bearer-token>" \
     http://localhost:3001/
```

**Expected Response:**
```
HTTP/1.1 400 Bad Request
WWW-Authenticate: DPoP error="invalid_request", error_description="Bearer tokens are not allowed (DPoP required)"

{
  "error": "invalid_request",
  "error_description": "Bearer tokens are not allowed (DPoP required)",
  "error_code": "bearer_not_allowed"
}
```

## Configuration

```go
middleware := jwtmiddleware.New(
    jwtmiddleware.WithValidator(jwtValidator),
    jwtmiddleware.WithDPoPMode(core.DPoPRequired),
    
    // Optional: Customize DPoP proof validation
    jwtmiddleware.WithDPoPProofOffset(60*time.Second),  // Proof valid for 60s
    jwtmiddleware.WithDPoPIATLeeway(30*time.Second),    // Allow 30s clock skew
)
```

## Key Features

1. **Enforced Security**: All requests must provide proof of possession
2. **Token Binding**: Tokens are cryptographically bound to client keys
3. **Replay Protection**: DPoP proofs include timestamp and are single-use
4. **Clear Error Messages**: Clients receive helpful error responses

## Use Cases

- **Financial APIs**: Banking, payments, trading platforms
- **Healthcare Systems**: HIPAA-compliant data access
- **Government Services**: Sensitive citizen data
- **Enterprise APIs**: Internal high-security services
- **Zero-Trust Networks**: All access requires proof of possession

## Security Benefits

✅ **Token Theft Protection**: Stolen tokens are useless without private key  
✅ **Replay Attack Prevention**: Each request requires fresh proof  
✅ **Man-in-the-Middle Protection**: Proof includes request URL/method  
✅ **Key Binding**: Token bound to specific cryptographic key pair  

## Migration Path

1. **Phase 1**: Start with DPoP Allowed mode (accept both)
2. **Phase 2**: Monitor adoption - track Bearer vs DPoP usage
3. **Phase 3**: Communicate migration timeline to clients
4. **Phase 4**: Switch to DPoP Required mode
5. **Phase 5**: Monitor errors and provide client support

## Error Responses

### Bearer Token Rejected
```json
{
  "error": "invalid_request",
  "error_description": "Bearer tokens are not allowed (DPoP required)",
  "error_code": "bearer_not_allowed"
}
```

### Missing DPoP Proof
```json
{
  "error": "invalid_dpop_proof",
  "error_description": "DPoP proof is required for DPoP-bound tokens",
  "error_code": "dpop_proof_missing"
}
```

### Invalid DPoP Proof
```json
{
  "error": "invalid_dpop_proof",
  "error_description": "DPoP proof JWT validation failed",
  "error_code": "dpop_proof_invalid"
}
```
