package validator

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// Validator to use with the jose v2 package.
type Validator struct {
	keyFunc            func(context.Context) (interface{}, error) // Required.
	signatureAlgorithm jose.SignatureAlgorithm                    // Required.
	expectedClaims     jwt.Expected                               // Internal.
	customClaims       func() CustomClaims                        // Optional.
	allowedClockSkew   time.Duration                              // Optional.
}

var allowedSigningAlgorithms = map[jose.SignatureAlgorithm]bool{
	jose.EdDSA: true,
	jose.HS256: true,
	jose.HS384: true,
	jose.HS512: true,
	jose.RS256: true,
	jose.RS384: true,
	jose.RS512: true,
	jose.ES256: true,
	jose.ES384: true,
	jose.ES512: true,
	jose.PS256: true,
	jose.PS384: true,
	jose.PS512: true,
}

// New sets up a new Validator with the required keyFunc
// and signatureAlgorithm as well as custom options.
func New(
	keyFunc func(context.Context) (interface{}, error),
	signatureAlgorithm jose.SignatureAlgorithm,
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
			Issuer:      issuerURL,
			AnyAudience: audience,
		},
	}

	for _, opt := range opts {
		opt(v)
	}

	return v, nil
}

// ValidateToken validates the passed in JWT using the jose v4 package.
func (v *Validator) ValidateToken(ctx context.Context, tokenString string) (interface{}, error) {
	token, err := jwt.ParseSigned(tokenString, []jose.SignatureAlgorithm{v.signatureAlgorithm})
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
	for _, value := range expectedClaims.AnyAudience {
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
