/*
Package validator provides JWT validation using the lestrrat-go/jwx v3 library.

This package implements the ValidateToken interface required by the middleware
and handles all aspects of JWT validation including signature verification,
registered claims validation, and custom claims support.

# Features

  - Signature verification using multiple algorithms (RS256, HS256, ES256, EdDSA, etc.)
  - Automatic validation of registered claims (iss, aud, exp, nbf, iat)
  - exp (expiration time) and nbf (not before) validated automatically - secure by default
  - Support for custom claims with validation logic
  - Clock skew tolerance for time-based claims
  - JWKS (JSON Web Key Set) support via key functions
  - Multiple issuer and audience support

# Supported Algorithms

The validator supports 14 signature algorithms:

HMAC:
  - HS256, HS384, HS512

RSA:
  - RS256, RS384, RS512 (RSASSA-PKCS1-v1_5)
  - PS256, PS384, PS512 (RSASSA-PSS)

ECDSA:
  - ES256, ES384, ES512
  - ES256K (secp256k1 curve)

EdDSA:
  - EdDSA (Ed25519)

# Basic Usage

	import (
	    "github.com/auth0/go-jwt-middleware/v3/validator"
	    "github.com/auth0/go-jwt-middleware/v3/jwks"
	)

	issuerURL, _ := url.Parse("https://auth.example.com/")

	// Create JWKS provider
	provider, err := jwks.NewCachingProvider(
	    jwks.WithIssuerURL(issuerURL),
	)
	if err != nil {
	    log.Fatal(err)
	}

	// Create validator
	v, err := validator.New(
	    validator.WithKeyFunc(provider.KeyFunc),
	    validator.WithAlgorithm(validator.RS256),
	    validator.WithIssuer(issuerURL.String()),
	    validator.WithAudience("my-api"),
	)
	if err != nil {
	    log.Fatal(err)
	}

	// Validate token
	claims, err := v.ValidateToken(ctx, tokenString)
	if err != nil {
	    // Token invalid
	}

	// Type assert to ValidatedClaims
	validatedClaims := claims.(*validator.ValidatedClaims)

Note: The validator automatically checks exp (expiration time) and nbf (not before)
claims - you don't need to validate these yourself. This is secure by default.

	}

	func (c *MyCustomClaims) Validate(ctx context.Context) error {
	    if c.Scope == "" {
	        return errors.New("scope is required")
	    }
	    return nil
	}

	// Use with validator
	v, err := validator.New(
	    validator.WithKeyFunc(keyFunc),
	    validator.WithAlgorithm(validator.RS256),
	    validator.WithIssuer("https://issuer.example.com/"),
	    validator.WithAudience("my-api"),
	    validator.WithCustomClaims(func() *MyCustomClaims {
	        return &MyCustomClaims{}
	    }),
	)

	// Access custom claims
	claims, _ := v.ValidateToken(ctx, tokenString)
	validatedClaims := claims.(*validator.ValidatedClaims)
	customClaims := validatedClaims.CustomClaims.(*MyCustomClaims)
	fmt.Println(customClaims.Scope)

# Multiple Issuers and Audiences

Support tokens from multiple issuers or for multiple audiences:

	// Static issuer list
	v, err := validator.New(
	    validator.WithKeyFunc(keyFunc),
	    validator.WithAlgorithm(validator.RS256),
	    validator.WithIssuers([]string{
	        "https://auth1.example.com/",
	        "https://auth2.example.com/",
	    }),
	    validator.WithAudiences([]string{
	        "api1",
	        "api2",
	    }),
	)

	// Dynamic issuer resolution (multi-tenant)
	v, err := validator.New(
	    validator.WithKeyFunc(keyFunc),
	    validator.WithAlgorithm(validator.RS256),
	    validator.WithIssuersResolver(func(ctx context.Context) ([]string, error) {
	        tenant := ctx.Value("tenant").(string)
	        return db.GetIssuersForTenant(ctx, tenant)
	    }),
	    validator.WithAudience("my-api"),
	)

# Clock Skew Tolerance

Allow time-based claims to be off by a certain duration:

	v, err := validator.New(
	    validator.WithKeyFunc(keyFunc),
	    validator.WithAlgorithm(validator.RS256),
	    validator.WithIssuer("https://issuer.example.com/"),
	    validator.WithAudience("my-api"),
	    validator.WithAllowedClockSkew(30*time.Second),
	)

This is useful when server clocks are slightly out of sync.
Default: 0 (no clock skew allowed)

# Using HMAC Algorithms

For symmetric key algorithms (HS256, HS384, HS512):

	secretKey := []byte("your-256-bit-secret")

	keyFunc := func(ctx context.Context) (any, error) {
	    return secretKey, nil
	}

	v, err := validator.New(
	    validator.WithKeyFunc(keyFunc),
	    validator.WithAlgorithm(validator.HS256),
	    validator.WithIssuer("https://issuer.example.com/"),
	    validator.WithAudience("my-api"),
	)

# Using RSA Public Keys

For asymmetric algorithms (RS256, PS256, ES256, etc.):

	import (
	    "crypto/rsa"
	    "crypto/x509"
	    "encoding/pem"
	)

	publicKeyPEM := []byte(`-----BEGIN PUBLIC KEY-----...`)

	block, _ := pem.Decode(publicKeyPEM)
	pubKey, _ := x509.ParsePKIXPublicKey(block.Bytes)
	rsaPublicKey := pubKey.(*rsa.PublicKey)

	keyFunc := func(ctx context.Context) (any, error) {
	    return rsaPublicKey, nil
	}

	v, err := validator.New(
	    validator.WithKeyFunc(keyFunc),
	    validator.WithAlgorithm(validator.RS256),
	    validator.WithIssuer("https://issuer.example.com/"),
	    validator.WithAudience("my-api"),
	)

# Validated Claims Structure

The ValidatedClaims struct contains both registered and custom claims:

	type ValidatedClaims struct {
	    RegisteredClaims RegisteredClaims // Standard JWT claims
	    CustomClaims     CustomClaims     // Your custom claims
	}

	type RegisteredClaims struct {
	    Issuer    string   // iss
	    Subject   string   // sub
	    Audience  []string // aud
	    ID        string   // jti
	    Expiry    int64    // exp (Unix timestamp)
	    NotBefore int64    // nbf (Unix timestamp)
	    IssuedAt  int64    // iat (Unix timestamp)
	}

# Error Handling

	claims, err := v.ValidateToken(ctx, tokenString)
	if err != nil {
	    // Token validation failed
	    // Possible reasons:
	    // - Invalid signature
	    // - Token expired
	    // - Token not yet valid
	    // - Invalid issuer
	    // - Invalid audience
	    // - Custom claims validation failed
	}

# Performance

The validator is optimized for performance:
  - Single-pass claim extraction
  - Minimal memory allocations
  - Direct JWT payload decoding for custom claims
  - Efficient string comparison for issuer/audience

Typical validation time:
  - With JWKS cache hit: <1ms
  - With JWKS cache miss: 50-200ms (network fetch)
  - HMAC validation: <0.1ms
  - RSA validation: <0.5ms

# Thread Safety

The Validator is immutable after creation and safe for concurrent use.
The same Validator instance can be used to validate multiple tokens
concurrently.

# Migration from go-jose v2

This package uses lestrrat-go/jwx v3 instead of square/go-jose v2.
Key differences:

1. Better performance and security
2. More comprehensive algorithm support
3. Improved JWKS handling with automatic kid matching
4. Native Go 1.18+ generics support
5. Active maintenance and updates

The API is designed to be familiar to go-jose users while leveraging
the improvements in jwx v3.
*/
package validator
