package validator

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gopkg.in/go-jose/go-jose.v2/jwt"
)

// Signature algorithms
const (
	EdDSA = SignatureAlgorithm("EdDSA")
	HS256 = SignatureAlgorithm("HS256") // HMAC using SHA-256
	HS384 = SignatureAlgorithm("HS384") // HMAC using SHA-384
	HS512 = SignatureAlgorithm("HS512") // HMAC using SHA-512
	RS256 = SignatureAlgorithm("RS256") // RSASSA-PKCS-v1.5 using SHA-256
	RS384 = SignatureAlgorithm("RS384") // RSASSA-PKCS-v1.5 using SHA-384
	RS512 = SignatureAlgorithm("RS512") // RSASSA-PKCS-v1.5 using SHA-512
	ES256 = SignatureAlgorithm("ES256") // ECDSA using P-256 and SHA-256
	ES384 = SignatureAlgorithm("ES384") // ECDSA using P-384 and SHA-384
	ES512 = SignatureAlgorithm("ES512") // ECDSA using P-521 and SHA-512
	PS256 = SignatureAlgorithm("PS256") // RSASSA-PSS using SHA256 and MGF1-SHA256
	PS384 = SignatureAlgorithm("PS384") // RSASSA-PSS using SHA384 and MGF1-SHA384
	PS512 = SignatureAlgorithm("PS512") // RSASSA-PSS using SHA512 and MGF1-SHA512
)

// Validator to use with the jose v2 package.
type Validator struct {
	keyFunc            func(context.Context) (interface{}, error) // Required.
	signatureAlgorithm SignatureAlgorithm                         // Required.
	expectedClaims     jwt.Expected                               // Internal.
	customClaims       func() CustomClaims                        // Optional.
	allowedClockSkew   time.Duration                              // Optional.
}

// SignatureAlgorithm is a signature algorithm.
type SignatureAlgorithm string

var allowedSigningAlgorithms = map[SignatureAlgorithm]bool{
	EdDSA: true,
	HS256: true,
	HS384: true,
	HS512: true,
	RS256: true,
	RS384: true,
	RS512: true,
	ES256: true,
	ES384: true,
	ES512: true,
	PS256: true,
	PS384: true,
	PS512: true,
}

// New sets up a new Validator with the required keyFunc
// and signatureAlgorithm as well as custom options.
func New(
	keyFunc func(context.Context) (interface{}, error),
	signatureAlgorithm SignatureAlgorithm,
	issuerURL string,
	audience []string,
	opts ...Option,
) (*Validator, error) {
	if keyFunc == nil {
		return nil, errors.New("keyFunc is required but was nil")
	}
	if issuerURL == "" {
		return nil, errors.New("issuer url is required but was empty")
	}
	if len(audience) == 0 {
		return nil, errors.New("audience is required but was empty")
	}
	if _, ok := allowedSigningAlgorithms[signatureAlgorithm]; !ok {
		return nil, errors.New("unsupported signature algorithm")
	}

	v := &Validator{
		keyFunc:            keyFunc,
		signatureAlgorithm: signatureAlgorithm,
		expectedClaims: jwt.Expected{
			Issuer:   issuerURL,
			Audience: audience,
		},
	}

	for _, opt := range opts {
		opt(v)
	}

	return v, nil
}

// ValidateToken validates the passed in JWT using the jose v2 package.
func (v *Validator) ValidateToken(ctx context.Context, tokenString string) (interface{}, error) {
	token, err := jwt.ParseSigned(tokenString)
	if err != nil {
		return nil, fmt.Errorf("could not parse the token: %w", err)
	}

	if err = validateSigningMethod(string(v.signatureAlgorithm), token.Headers[0].Algorithm); err != nil {
		return nil, fmt.Errorf("signing method is invalid: %w", err)
	}

	registeredClaims, customClaims, err := v.deserializeClaims(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize token claims: %w", err)
	}

	if err = validateClaimsWithLeeway(registeredClaims, v.expectedClaims, v.allowedClockSkew); err != nil {
		return nil, fmt.Errorf("expected claims not validated: %w", err)
	}

	if customClaims != nil {
		if err = customClaims.Validate(ctx); err != nil {
			return nil, fmt.Errorf("custom claims not validated: %w", err)
		}
	}

	validatedClaims := &ValidatedClaims{
		RegisteredClaims: RegisteredClaims{
			Issuer:    registeredClaims.Issuer,
			Subject:   registeredClaims.Subject,
			Audience:  registeredClaims.Audience,
			ID:        registeredClaims.ID,
			Expiry:    numericDateToUnixTime(registeredClaims.Expiry),
			NotBefore: numericDateToUnixTime(registeredClaims.NotBefore),
			IssuedAt:  numericDateToUnixTime(registeredClaims.IssuedAt),
		},
		CustomClaims: customClaims,
	}

	return validatedClaims, nil
}

func validateClaimsWithLeeway(actualClaims jwt.Claims, expected jwt.Expected, leeway time.Duration) error {
	expectedClaims := expected
	expectedClaims.Time = time.Now()

	if actualClaims.Issuer != expectedClaims.Issuer {
		return jwt.ErrInvalidIssuer
	}

	foundAudience := false
	for _, value := range expectedClaims.Audience {
		if actualClaims.Audience.Contains(value) {
			foundAudience = true
			break
		}
	}
	if !foundAudience {
		return jwt.ErrInvalidAudience
	}

	if actualClaims.NotBefore != nil && expectedClaims.Time.Add(leeway).Before(actualClaims.NotBefore.Time()) {
		return jwt.ErrNotValidYet
	}

	if actualClaims.Expiry != nil && expectedClaims.Time.Add(-leeway).After(actualClaims.Expiry.Time()) {
		return jwt.ErrExpired
	}

	if actualClaims.IssuedAt != nil && expectedClaims.Time.Add(leeway).Before(actualClaims.IssuedAt.Time()) {
		return jwt.ErrIssuedInTheFuture
	}

	return nil
}

func validateSigningMethod(validAlg, tokenAlg string) error {
	if validAlg != tokenAlg {
		return fmt.Errorf("expected %q signing algorithm but token specified %q", validAlg, tokenAlg)
	}
	return nil
}

func (v *Validator) customClaimsExist() bool {
	return v.customClaims != nil && v.customClaims() != nil
}

func (v *Validator) deserializeClaims(ctx context.Context, token *jwt.JSONWebToken) (jwt.Claims, CustomClaims, error) {
	key, err := v.keyFunc(ctx)
	if err != nil {
		return jwt.Claims{}, nil, fmt.Errorf("error getting the keys from the key func: %w", err)
	}

	claims := []interface{}{&jwt.Claims{}}
	if v.customClaimsExist() {
		claims = append(claims, v.customClaims())
	}

	if err = token.Claims(key, claims...); err != nil {
		return jwt.Claims{}, nil, fmt.Errorf("could not get token claims: %w", err)
	}

	registeredClaims := *claims[0].(*jwt.Claims)

	var customClaims CustomClaims
	if len(claims) > 1 {
		customClaims = claims[1].(CustomClaims)
	}

	return registeredClaims, customClaims, nil
}

func numericDateToUnixTime(date *jwt.NumericDate) int64 {
	if date != nil {
		return date.Time().Unix()
	}
	return 0
}
