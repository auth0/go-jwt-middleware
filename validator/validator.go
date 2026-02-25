package validator

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/auth0/go-jwt-middleware/v3/core"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// contextKey is an unexported type for context keys to prevent collisions.
// Using an unexported type ensures that only this package can create context keys,
// eliminating the risk of collisions with other packages.
type contextKey int

const (
	// issuerContextKey is the context key for storing the validated issuer.
	issuerContextKey contextKey = iota
)

// IssuerFromContext extracts the validated issuer from the context.
// This is useful for JWKS providers that need to route requests based on the issuer.
//
// Returns the issuer string and true if found, or empty string and false if not present.
func IssuerFromContext(ctx context.Context) (string, bool) {
	issuer, ok := ctx.Value(issuerContextKey).(string)
	return issuer, ok
}

// SetIssuerInContext stores the issuer in the context.
// This is primarily used for testing purposes. In production, the issuer is automatically
// set by ValidateToken after validation.
func SetIssuerInContext(ctx context.Context, issuer string) context.Context {
	return context.WithValue(ctx, issuerContextKey, issuer)
}

// Signature algorithms
const (
	EdDSA  = SignatureAlgorithm("EdDSA")
	HS256  = SignatureAlgorithm("HS256")  // HMAC using SHA-256
	HS384  = SignatureAlgorithm("HS384")  // HMAC using SHA-384
	HS512  = SignatureAlgorithm("HS512")  // HMAC using SHA-512
	RS256  = SignatureAlgorithm("RS256")  // RSASSA-PKCS-v1.5 using SHA-256
	RS384  = SignatureAlgorithm("RS384")  // RSASSA-PKCS-v1.5 using SHA-384
	RS512  = SignatureAlgorithm("RS512")  // RSASSA-PKCS-v1.5 using SHA-512
	ES256  = SignatureAlgorithm("ES256")  // ECDSA using P-256 and SHA-256
	ES384  = SignatureAlgorithm("ES384")  // ECDSA using P-384 and SHA-384
	ES512  = SignatureAlgorithm("ES512")  // ECDSA using P-521 and SHA-512
	ES256K = SignatureAlgorithm("ES256K") // ECDSA using secp256k1 curve and SHA-256
	PS256  = SignatureAlgorithm("PS256")  // RSASSA-PSS using SHA256 and MGF1-SHA256
	PS384  = SignatureAlgorithm("PS384")  // RSASSA-PSS using SHA384 and MGF1-SHA384
	PS512  = SignatureAlgorithm("PS512")  // RSASSA-PSS using SHA512 and MGF1-SHA512
)

// Validator validates JWTs using the jwx v3 library.
type Validator struct {
	keyFunc           func(context.Context) (any, error)          // Required.
	allowedAlgorithms []SignatureAlgorithm                        // Required.
	expectedIssuers   []string                                    // Required (unless issuersResolver is set).
	expectedAudiences []string                                    // Required.
	customClaims      func() CustomClaims                         // Optional.
	allowedClockSkew  time.Duration                               // Optional.
	issuersResolver   func(ctx context.Context) ([]string, error) // Optional: dynamic issuer resolution.
}

// SignatureAlgorithm is a signature algorithm.
type SignatureAlgorithm string

var allowedSigningAlgorithms = map[SignatureAlgorithm]bool{
	EdDSA:  true,
	HS256:  true,
	HS384:  true,
	HS512:  true,
	RS256:  true,
	RS384:  true,
	RS512:  true,
	ES256:  true,
	ES384:  true,
	ES512:  true,
	ES256K: true,
	PS256:  true,
	PS384:  true,
	PS512:  true,
}

// allowedDPoPAlgorithms contains only asymmetric algorithms per RFC 9449 Section 4.3.2.
// DPoP proofs MUST use asymmetric (public key) cryptographic algorithms.
// Symmetric algorithms (HS*) are explicitly excluded because using shared secrets
// would defeat the sender-constraining purpose of DPoP.
// ES256K (secp256k1 curve) is excluded as it's not standardized for DPoP in RFC 9449.
var allowedDPoPAlgorithms = map[SignatureAlgorithm]bool{
	EdDSA: true, // Edwards-curve Digital Signature Algorithm
	RS256: true, // RSASSA-PKCS1-v1_5 using SHA-256
	RS384: true, // RSASSA-PKCS1-v1_5 using SHA-384
	RS512: true, // RSASSA-PKCS1-v1_5 using SHA-512
	ES256: true, // ECDSA using P-256 and SHA-256
	ES384: true, // ECDSA using P-384 and SHA-384
	ES512: true, // ECDSA using P-521 and SHA-512
	PS256: true, // RSASSA-PSS using SHA-256 and MGF1-SHA256
	PS384: true, // RSASSA-PSS using SHA-384 and MGF1-SHA384
	PS512: true, // RSASSA-PSS using SHA-512 and MGF1-SHA512
}

// DPoPSupportedAlgorithms is a space-separated list of supported DPoP algorithms
// for use in WWW-Authenticate headers per RFC 9449 Section 7.1.
const DPoPSupportedAlgorithms = "ES256 ES384 ES512 RS256 RS384 RS512 PS256 PS384 PS512 EdDSA"

// New creates a new Validator with the provided options.
//
// Required options:
//   - WithKeyFunc: Function to provide verification key(s)
//   - WithAlgorithm: Signature algorithm to validate
//   - WithIssuer, WithIssuers, or WithIssuersResolver: Expected issuer claim(s) (iss)
//   - WithAudience or WithAudiences: Expected audience claim(s) (aud)
//
// Optional options:
//   - WithCustomClaims: Custom claims validation
//   - WithAllowedClockSkew: Clock skew tolerance for time-based claims (default: 0)
//
// Example:
//
//	validator, err := validator.New(
//	    validator.WithKeyFunc(keyFunc),
//	    validator.WithAlgorithm(validator.RS256),
//	    validator.WithIssuer("https://issuer.example.com/"),
//	    validator.WithAudience("my-api"),
//	    validator.WithAllowedClockSkew(30*time.Second),
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
func New(opts ...Option) (*Validator, error) {
	v := &Validator{
		allowedClockSkew: 0, // Secure default: no clock skew
	}

	// Apply all options
	for _, opt := range opts {
		if err := opt(v); err != nil {
			return nil, fmt.Errorf("invalid option: %w", err)
		}
	}

	// Validate required configuration
	if err := v.validate(); err != nil {
		return nil, fmt.Errorf("invalid validator configuration: %w", err)
	}

	return v, nil
}

// validate ensures all required fields are set.
func (v *Validator) validate() error {
	var errs []error

	if v.keyFunc == nil {
		errs = append(errs, errors.New("keyFunc is required (use WithKeyFunc)"))
	}
	if len(v.allowedAlgorithms) == 0 {
		errs = append(errs, errors.New("signature algorithm is required (use WithAlgorithm or WithAlgorithms)"))
	}
	// Either expectedIssuers or issuersResolver must be set (but not both)
	if len(v.expectedIssuers) == 0 && v.issuersResolver == nil {
		errs = append(errs, errors.New("issuer is required (use WithIssuer, WithIssuers, or WithIssuersResolver)"))
	}
	if len(v.expectedAudiences) == 0 {
		errs = append(errs, errors.New("audience is required (use WithAudience or WithAudiences)"))
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// ValidateToken validates the passed in JWT.
// This method is optimized for performance and abstracts the underlying JWT library.
//
// Security: The issuer is validated BEFORE fetching JWKS to prevent SSRF attacks.
// This ensures that the issuer claim is trusted before making external requests.
func (v *Validator) ValidateToken(ctx context.Context, tokenString string) (any, error) {
	// Step 1: Parse JWS envelope in a single pass (no signature verification).
	// This gives us both the algorithm header and unverified claims without
	// needing separate jwt.ParseInsecure + manual header decode.
	msg, err := jws.Parse([]byte(tokenString))
	if err != nil {
		return nil, core.NewValidationError(core.ErrorCodeTokenMalformed, "failed to parse token", err)
	}

	// Step 1a: Validate token algorithm against allowed list (fail-fast).
	// Rejects tokens with disallowed algorithms before JWKS fetch or signature verification.
	sigs := msg.Signatures()
	if len(sigs) == 0 {
		return nil, core.NewValidationError(core.ErrorCodeTokenMalformed, "token has no signatures", nil)
	}
	tokenAlg, ok := sigs[0].ProtectedHeaders().Algorithm()
	if !ok {
		return nil, core.NewValidationError(core.ErrorCodeTokenMalformed, "token header missing required alg field", nil)
	}
	algStr := tokenAlg.String()
	algAllowed := false
	for _, allowed := range v.allowedAlgorithms {
		if string(allowed) == algStr {
			algAllowed = true
			break
		}
	}
	if !algAllowed {
		return nil, core.NewValidationError(core.ErrorCodeInvalidAlgorithm, fmt.Sprintf("token algorithm %q is not allowed (allowed: %v)", algStr, v.allowedAlgorithms), nil)
	}

	// Step 1b: Extract issuer from unverified payload.
	var unverifiedClaims struct {
		Issuer string `json:"iss"`
	}
	if err := json.Unmarshal(msg.Payload(), &unverifiedClaims); err != nil {
		return nil, core.NewValidationError(core.ErrorCodeTokenMalformed, "failed to parse token claims", err)
	}
	issuer := unverifiedClaims.Issuer
	if issuer == "" {
		return nil, core.NewValidationError(core.ErrorCodeInvalidIssuer, "token has no issuer claim", nil)
	}

	// Step 2: Pass unverified issuer into context so that the resolver
	// has access to the iss claim for dynamic issuer resolution.
	ctx = SetIssuerInContext(ctx, issuer)

	// Step 3: Validate issuer BEFORE fetching JWKS (security: prevents SSRF)
	if err := v.validateIssuerWithResolver(ctx, issuer); err != nil {
		return nil, core.NewValidationError(core.ErrorCodeInvalidIssuer, "issuer validation failed", err)
	}

	// Step 4: Get the verification key (now safe to fetch from validated issuer)
	key, err := v.keyFunc(ctx)
	if err != nil {
		return nil, core.NewValidationError(core.ErrorCodeJWKSFetchFailed, "error getting the keys from the key func", err)
	}

	// Step 5: Parse and validate token signature using the key
	token, err := v.parseToken(ctx, tokenString, key)
	if err != nil {
		return nil, err
	}

	// Step 6: Extract and validate remaining claims (optimized: single pass through token)
	validatedClaims, err := v.extractAndValidateClaims(ctx, token, tokenString)
	if err != nil {
		return nil, err
	}

	return validatedClaims, nil
}

// parseToken parses and performs basic validation on the token.
// Abstraction point: This method wraps the underlying JWT library's parsing.
func (v *Validator) parseToken(_ context.Context, tokenString string, key any) (jwt.Token, error) {
	parseOpts := []jwt.ParseOption{
		jwt.WithAcceptableSkew(v.allowedClockSkew),
		jwt.WithValidate(true),
	}

	// Handle both single keys and JWK sets.
	// When using JWKS providers, key will be jwk.Set - use WithKeySet to automatically
	// select the correct key based on the token's kid header and embedded alg.
	// WithUseDefault(true) enables fallback: if the set has exactly one key and the
	// token has no kid header, that key is used. This is required for symmetric MCD
	// (HS256 keys typically don't use kid) and is safe because algorithm enforcement
	// already happened in ValidateToken before reaching this point.
	// For single keys (byte slices, etc.), use WithKey with the configured algorithm.
	switch k := key.(type) {
	case jwk.Set:
		parseOpts = append(parseOpts, jwt.WithKeySet(k, jws.WithUseDefault(true)))
	default:
		if len(v.allowedAlgorithms) != 1 {
			return nil, fmt.Errorf(
				"multiple algorithms configured (%v) but key provider returned a raw key; "+
					"use a key provider that returns jwk.Set (e.g., MultiIssuerProvider with "+
					"WithIssuerKeyConfig), or use WithAlgorithm with a single algorithm for raw keys",
				v.allowedAlgorithms,
			)
		}
		jwxAlg, err := stringToJWXAlgorithm(string(v.allowedAlgorithms[0]))
		if err != nil {
			return nil, fmt.Errorf("unsupported algorithm: %w", err)
		}
		parseOpts = append(parseOpts, jwt.WithKey(jwxAlg, key))
	}

	token, err := jwt.ParseString(tokenString, parseOpts...)
	if err != nil {
		errStr := err.Error()
		switch {
		case strings.Contains(errStr, "signature verification failed"):
			return nil, core.NewValidationError(core.ErrorCodeInvalidSignature, "failed to parse and validate token", err)
		case strings.Contains(errStr, `"exp" not satisfied`):
			return nil, core.NewValidationError(core.ErrorCodeTokenExpired, "failed to parse and validate token", err)
		case strings.Contains(errStr, `"nbf" not satisfied`):
			return nil, core.NewValidationError(core.ErrorCodeTokenNotYetValid, "failed to parse and validate token", err)
		case strings.Contains(errStr, `"iat" not satisfied`):
			return nil, core.NewValidationError(core.ErrorCodeTokenNotYetValid, "failed to parse and validate token", err)
		case strings.Contains(errStr, "failed to find key with key ID"):
			return nil, core.NewValidationError(core.ErrorCodeJWKSKeyNotFound, "failed to parse and validate token", err)
		default:
			return nil, core.NewValidationError(core.ErrorCodeTokenMalformed, "failed to parse and validate token", err)
		}
	}

	return token, nil
}

// extractAndValidateClaims extracts claims from the token and validates them.
// Optimized to minimize method calls and allocations.
// Note: Issuer is validated earlier in ValidateToken (before JWKS fetch) for security.
func (v *Validator) extractAndValidateClaims(ctx context.Context, token jwt.Token, tokenString string) (*ValidatedClaims, error) {
	// Extract registered claims in a single pass
	issuer, _ := token.Issuer()
	subject, _ := token.Subject()
	audience, _ := token.Audience()
	jwtID, _ := token.JwtID()
	expiration, _ := token.Expiration()
	notBefore, _ := token.NotBefore()
	issuedAt, _ := token.IssuedAt()

	// Validate audience (issuer already validated in ValidateToken before JWKS fetch)
	if err := v.validateAudience(audience); err != nil {
		return nil, core.NewValidationError(core.ErrorCodeInvalidAudience, "audience validation failed", err)
	}

	registeredClaims := RegisteredClaims{
		Issuer:    issuer,
		Subject:   subject,
		Audience:  audience,
		ID:        jwtID,
		Expiry:    timeToUnix(expiration),
		NotBefore: timeToUnix(notBefore),
		IssuedAt:  timeToUnix(issuedAt),
	}

	// Handle custom claims if configured
	var customClaims CustomClaims
	if v.customClaimsExist() {
		var err error
		customClaims, err = v.extractCustomClaims(ctx, tokenString)
		if err != nil {
			return nil, err
		}
	}

	// Extract cnf (confirmation) claim for DPoP binding if present
	var confirmationClaim *ConfirmationClaim
	cnf, err := v.extractConfirmationClaim(tokenString)
	if err != nil {
		// Don't fail if cnf extraction fails - it's optional
		// The cnf claim may not be present for Bearer tokens
	} else if cnf != nil {
		confirmationClaim = cnf
	}

	return &ValidatedClaims{
		RegisteredClaims:  registeredClaims,
		CustomClaims:      customClaims,
		ConfirmationClaim: confirmationClaim,
	}, nil
}

// extractCustomClaims extracts and validates custom claims from the token string.
// SDK-agnostic approach: Manually decodes JWT payload for maximum portability and performance.
// This allows swapping the underlying JWT library without changing this logic.
func (v *Validator) extractCustomClaims(ctx context.Context, tokenString string) (CustomClaims, error) {
	customClaims := v.customClaims()

	// JWT format: header.payload.signature
	// Extract and decode the payload (second part) directly
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, core.NewValidationError(core.ErrorCodeTokenMalformed, fmt.Sprintf("invalid JWT format: expected 3 parts, got %d", len(parts)), nil)
	}

	// Decode the payload using base64url encoding (JWT standard)
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, core.NewValidationError(core.ErrorCodeTokenMalformed, "failed to decode JWT payload", err)
	}

	// Unmarshal JSON payload into custom claims struct
	if err := json.Unmarshal(payloadJSON, customClaims); err != nil {
		return nil, core.NewValidationError(core.ErrorCodeTokenMalformed, "failed to unmarshal custom claims", err)
	}

	// Validate the custom claims
	if err := customClaims.Validate(ctx); err != nil {
		return nil, core.NewValidationError(core.ErrorCodeInvalidClaims, "custom claims not validated", err)
	}

	return customClaims, nil
}

func (v *Validator) customClaimsExist() bool {
	return v.customClaims != nil && v.customClaims() != nil
}

// extractConfirmationClaim extracts the cnf (confirmation) claim from the token string.
// This claim is used for DPoP (Demonstrating Proof-of-Possession) token binding per RFC 7800 and RFC 9449.
// Returns nil if the cnf claim is not present (which is normal for Bearer tokens).
func (v *Validator) extractConfirmationClaim(tokenString string) (*ConfirmationClaim, error) {
	// JWT format: header.payload.signature
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	// Decode the payload using base64url encoding
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	// Unmarshal only the cnf claim from the payload
	var payload struct {
		Cnf *ConfirmationClaim `json:"cnf,omitempty"`
	}
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal payload: %w", err)
	}

	// Return nil if cnf claim is not present (normal for Bearer tokens)
	return payload.Cnf, nil
}

// validateIssuer checks if the token issuer matches one of the expected issuers.
func (v *Validator) validateIssuer(issuer string) error {
	for _, expectedIssuer := range v.expectedIssuers {
		if issuer == expectedIssuer {
			return nil
		}
	}
	return core.NewValidationError(core.ErrorCodeInvalidIssuer, fmt.Sprintf("token issuer %q does not match any expected issuer", issuer), nil)
}

// validateIssuerWithResolver checks if the token issuer is valid using either
// the static expectedIssuers list or the dynamic issuersResolver function.
// This method should be called BEFORE fetching JWKS to prevent SSRF attacks.
func (v *Validator) validateIssuerWithResolver(ctx context.Context, issuer string) error {
	if issuer == "" {
		return core.NewValidationError(core.ErrorCodeInvalidIssuer, "token has no issuer", nil)
	}

	// Use dynamic resolver if configured
	if v.issuersResolver != nil {
		validIssuers, err := v.issuersResolver(ctx)
		if err != nil {
			return fmt.Errorf("failed to resolve issuers: %w", err)
		}

		// Check if issuer is in the resolved list
		for _, expected := range validIssuers {
			if issuer == expected {
				return nil
			}
		}
		return core.NewValidationError(core.ErrorCodeInvalidIssuer, fmt.Sprintf("issuer %q not allowed by resolver", issuer), nil)
	}

	// Fall back to static issuer validation
	return v.validateIssuer(issuer)
}

// validateAudience checks if the token audiences contain at least one expected audience.
func (v *Validator) validateAudience(tokenAudiences []string) error {
	// Token must have at least one audience
	if len(tokenAudiences) == 0 {
		return core.NewValidationError(core.ErrorCodeInvalidAudience, "token has no audience", nil)
	}

	// Check if token contains at least one expected audience
	for _, tokenAud := range tokenAudiences {
		for _, expectedAud := range v.expectedAudiences {
			if tokenAud == expectedAud {
				return nil
			}
		}
	}

	return core.NewValidationError(core.ErrorCodeInvalidAudience, fmt.Sprintf("token audience %v does not match any expected audience %v", tokenAudiences, v.expectedAudiences), nil)
}

// stringToJWXAlgorithm converts our string algorithm to jwx's jwa.SignatureAlgorithm.
func stringToJWXAlgorithm(alg string) (jwa.SignatureAlgorithm, error) {
	switch SignatureAlgorithm(alg) {
	case HS256:
		return jwa.HS256(), nil
	case HS384:
		return jwa.HS384(), nil
	case HS512:
		return jwa.HS512(), nil
	case RS256:
		return jwa.RS256(), nil
	case RS384:
		return jwa.RS384(), nil
	case RS512:
		return jwa.RS512(), nil
	case ES256:
		return jwa.ES256(), nil
	case ES384:
		return jwa.ES384(), nil
	case ES512:
		return jwa.ES512(), nil
	case ES256K:
		return jwa.ES256K(), nil
	case PS256:
		return jwa.PS256(), nil
	case PS384:
		return jwa.PS384(), nil
	case PS512:
		return jwa.PS512(), nil
	case EdDSA:
		return jwa.EdDSA(), nil
	default:
		var zero jwa.SignatureAlgorithm
		return zero, fmt.Errorf("unsupported algorithm: %s", alg)
	}
}

// timeToUnix converts a time.Time to Unix timestamp, returning 0 for zero time.
func timeToUnix(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}
