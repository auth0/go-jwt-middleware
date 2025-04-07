package validator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// SignatureAlgorithm is a signature algorithm.
type SignatureAlgorithm string

// Issuer represents a JWT issuer.
type Issuer string

// Audience represents a JWT audience.
type Audience []string

// KeyFunc is a function that returns the key for validating a token.
type KeyFunc func(context.Context) (interface{}, error)

// Supported values for SignatureAlgorithm
const (
	ES256  SignatureAlgorithm = "ES256"  // ECDSA using P-256 and SHA-256
	ES256K SignatureAlgorithm = "ES256K" // ECDSA using secp256k1 and SHA-256
	ES384  SignatureAlgorithm = "ES384"  // ECDSA using P-384 and SHA-384
	ES512  SignatureAlgorithm = "ES512"  // ECDSA using P-521 and SHA-512
	EdDSA  SignatureAlgorithm = "EdDSA"  // EdDSA signature algorithms
	HS256  SignatureAlgorithm = "HS256"  // HMAC using SHA-256
	HS384  SignatureAlgorithm = "HS384"  // HMAC using SHA-384
	HS512  SignatureAlgorithm = "HS512"  // HMAC using SHA-512
	PS256  SignatureAlgorithm = "PS256"  // RSASSA-PSS using SHA256 and MGF1-SHA256
	PS384  SignatureAlgorithm = "PS384"  // RSASSA-PSS using SHA384 and MGF1-SHA384
	PS512  SignatureAlgorithm = "PS512"  // RSASSA-PSS using SHA512 and MGF1-SHA512
	RS256  SignatureAlgorithm = "RS256"  // RSASSA-PKCS-v1.5 using SHA-256
	RS384  SignatureAlgorithm = "RS384"  // RSASSA-PKCS-v1.5 using SHA-384
	RS512  SignatureAlgorithm = "RS512"  // RSASSA-PKCS-v1.5 using SHA-512
)

// Error definitions
var (
	ErrKeyFuncRequired      = errors.New("keyFunc is required but was nil")
	ErrIssuerURLRequired    = errors.New("issuer URL is required but was empty")
	ErrAudienceRequired     = errors.New("audience is required but was empty")
	ErrSignatureAlgRequired = errors.New("signature algorithm is required")
	ErrUnsupportedAlgorithm = errors.New("unsupported signature algorithm")
	ErrTokenMalformed       = errors.New("token is malformed")
	ErrTokenInvalid         = errors.New("token validation failed")
	ErrClaimsMappingFailed  = errors.New("failed to map custom claims")
)

// JWA algorithm mapping
var jwaAlgorithms = map[SignatureAlgorithm]jwa.SignatureAlgorithm{
	EdDSA:  jwa.EdDSA,
	HS256:  jwa.HS256,
	HS384:  jwa.HS384,
	HS512:  jwa.HS512,
	RS256:  jwa.RS256,
	RS384:  jwa.RS384,
	RS512:  jwa.RS512,
	ES256:  jwa.ES256,
	ES384:  jwa.ES384,
	ES512:  jwa.ES512,
	PS256:  jwa.PS256,
	PS384:  jwa.PS384,
	PS512:  jwa.PS512,
	ES256K: jwa.ES256K,
}

// Validator for JWT tokens using lestrrat-go/jwx
type Validator struct {
	keyFunc              func(context.Context) (interface{}, error)
	signatureAlgorithm   SignatureAlgorithm
	customClaims         func() CustomClaims
	allowedClockSkew     time.Duration
	expectedIssuers      []string
	expectedAudience     []string
	skipIssuerValidation bool
}

// ValidatorOption represents a functional option for configuring a Validator.
type Option func(*Validator) error

// New creates a new Validator with the provided options.
// It requires at minimum:
// - WithKeyFunc: to provide the key for token validation
// - WithSignatureAlgorithm: to specify the algorithm for token validation
// - WithAudience: to specify the expected audience
// Unless WithSkipIssuerValidation is specified, it also requires:
// - WithIssuer or WithIssuers: to specify the expected issuer(s)
func New(options ...Option) (*Validator, error) {
	v := &Validator{}

	// Apply all options
	for _, opt := range options {
		if err := opt(v); err != nil {
			return nil, err
		}
	}

	// Validate required options
	if v.keyFunc == nil {
		return nil, ErrKeyFuncRequired
	}

	if v.signatureAlgorithm == "" {
		return nil, ErrSignatureAlgRequired
	}

	if _, ok := jwaAlgorithms[v.signatureAlgorithm]; !ok {
		return nil, ErrUnsupportedAlgorithm
	}

	if len(v.expectedAudience) == 0 {
		return nil, ErrAudienceRequired
	}

	// Only validate issuers if skip validation is not enabled
	if !v.skipIssuerValidation && len(v.expectedIssuers) == 0 {
		return nil, ErrIssuerURLRequired
	}

	return v, nil
}

// ValidateToken validates the JWT token and returns the validated claims
func (v *Validator) ValidateToken(ctx context.Context, tokenString string) (interface{}, error) {
	if tokenString == "" {
		return nil, ErrTokenMalformed
	}

	// Get the key to validate the token
	key, err := v.keyFunc(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get key: %w", err)
	}
	// Parse and validate the token in a single step
	parseOpts := []jwt.ParseOption{
		jwt.WithValidate(true),
		jwt.WithVerify(true),
		jwt.WithKey(jwa.SignatureAlgorithm(v.signatureAlgorithm), key),
	}

	// Add clock skew option if configured
	if v.allowedClockSkew > 0 {
		parseOpts = append(parseOpts, jwt.WithAcceptableSkew(v.allowedClockSkew))
	}

	token, err := jwt.Parse([]byte(tokenString), parseOpts...)
	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	// Validate issuer if validation is not skipped
	if !v.skipIssuerValidation {
		expectedIssuers := make(map[string]struct{}, len(v.expectedIssuers))
		for _, issuer := range v.expectedIssuers {
			expectedIssuers[issuer] = struct{}{}
		}

		if _, ok := expectedIssuers[token.Issuer()]; !ok {
			return nil, fmt.Errorf("token issuer %q not in allowed issuers list", token.Issuer())
		}
	}

	// Validate audience claims
	tokenAudiences := token.Audience()
	if len(tokenAudiences) == 0 {
		return nil, fmt.Errorf("token validation failed: missing audience claim")
	}

	// Check for intersection between token audiences and expected audiences
	expectedAudMap := make(map[string]struct{}, len(v.expectedAudience))
	for _, aud := range v.expectedAudience {
		expectedAudMap[aud] = struct{}{}
	}

	validAudience := false
	for _, aud := range token.Audience() {
		if _, exists := expectedAudMap[aud]; exists {
			validAudience = true
			break
		}
	}

	if !validAudience {
		return nil, fmt.Errorf("token validation failed: invalid audience claim")
	}

	// Extract standard JWT claims
	registeredClaims := RegisteredClaims{
		Issuer:   token.Issuer(),
		Subject:  token.Subject(),
		Audience: token.Audience(),
		ID:       token.JwtID(),
	}

	if exp := token.Expiration(); !exp.IsZero() {
		registeredClaims.Expiry = exp.Unix()
	}

	if nbf := token.NotBefore(); !nbf.IsZero() {
		registeredClaims.NotBefore = nbf.Unix()
	}

	if iat := token.IssuedAt(); !iat.IsZero() {
		registeredClaims.IssuedAt = iat.Unix()
	}

	validatedClaims := &ValidatedClaims{
		RegisteredClaims: registeredClaims,
	}

	// Process custom claims if configured
	if v.customClaimsExist() {
		customClaims := v.customClaims()

		// Convert token to map representation
		tokenMap, err := token.AsMap(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to convert token to map: %w", err)
		}

		// Transform token map to custom claims via JSON
		jsonData, err := json.Marshal(tokenMap)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal token data: %w", err)
		}

		if err = json.Unmarshal(jsonData, customClaims); err != nil {
			return nil, ErrClaimsMappingFailed
		}

		// Run custom validation on claims
		if err = customClaims.Validate(ctx); err != nil {
			return nil, fmt.Errorf("custom claims validation failed: %w", err)
		}

		validatedClaims.CustomClaims = customClaims
	}

	return validatedClaims, nil
}

// customClaimsExist checks if the validator has a non-nil custom claims function
// that returns a non-nil value
func (v *Validator) customClaimsExist() bool {
	return v.customClaims != nil && v.customClaims() != nil
}
