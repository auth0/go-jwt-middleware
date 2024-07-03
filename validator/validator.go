package validator

import (
	"context"
	"errors"
	"fmt"
	"github.com/go-jose/go-jose/v4"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
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
	expectedClaims     []jwt.Expected                             // Internal.
	customClaims       func() CustomClaims                        // Optional.
	allowedClockSkew   time.Duration                              // Optional.
}

// SignatureAlgorithm is a signature algorithm.
type SignatureAlgorithm jose.SignatureAlgorithm
type SignatureAlgorithms []jose.SignatureAlgorithm

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
	if _, ok := allowedSigningAlgorithms[signatureAlgorithm]; !ok {
		return nil, errors.New("unsupported signature algorithm")
	}

	v := &Validator{
		keyFunc:            keyFunc,
		signatureAlgorithm: signatureAlgorithm,
		expectedClaims:     make([]jwt.Expected, 0),
	}

	for _, opt := range opts {
		opt(v)
	}

	if len(v.expectedClaims) == 0 && issuerURL == "" {
		return nil, errors.New("issuer url is required but was empty")
	} else if len(v.expectedClaims) == 0 && len(audience) == 0 {
		return nil, errors.New("audience is required but was empty")
	} else if len(issuerURL) > 0 && len(audience) > 0 {
		v.expectedClaims = append(v.expectedClaims, jwt.Expected{
			Issuer:      issuerURL,
			AnyAudience: audience,
		})
	}

	if len(v.expectedClaims) == 0 {
		return nil, errors.New("expected claims but none provided")
	}

	for i, expected := range v.expectedClaims {
		if expected.Issuer == "" {
			return nil, fmt.Errorf("issuer url %d is required but was empty", i)
		}
		if len(expected.AnyAudience) == 0 {
			return nil, fmt.Errorf("audience %d is required but was empty", i)
		}
	}

	return v, nil
}

// NewValidator sets up a new Validator with the required keyFunc
// and signatureAlgorithm as well as custom options.
// This function has been added to provide an alternate function without the required issuer or audience parameters
// so they can be included in the opts parameter via WithExpectedClaims
// This function operates exactly like New with the exception of the two parameters issuer and audience and this function
// expects the inclusion of WithExpectedClaims with at least one valid expected claim.
// A valid expected claim would include an issuer and at least one audience
func NewValidator(
	keyFunc func(context.Context) (interface{}, error),
	signatureAlgorithm SignatureAlgorithm,
	opts ...Option,
) (*Validator, error) {
	if keyFunc == nil {
		return nil, errors.New("keyFunc is required but was nil")
	}
	if _, ok := allowedSigningAlgorithms[signatureAlgorithm]; !ok {
		return nil, errors.New("unsupported signature algorithm")
	}

	v := &Validator{
		keyFunc:            keyFunc,
		signatureAlgorithm: signatureAlgorithm,
		expectedClaims:     make([]jwt.Expected, 0),
	}

	for _, opt := range opts {
		opt(v)
	}

	if len(v.expectedClaims) == 0 {
		return nil, errors.New("expected claims but none provided")
	}

	for i, expected := range v.expectedClaims {
		if expected.Issuer == "" {
			return nil, fmt.Errorf("issuer url %d is required but was empty", i)
		}
		if len(expected.AnyAudience) == 0 {
			return nil, fmt.Errorf("audience %d is required but was empty", i)
		}
	}

	return v, nil
}

// ValidateToken validates the passed in JWT using the jose v2 package.
func (v *Validator) ValidateToken(ctx context.Context, tokenString string) (interface{}, error) {
	token, err := jwt.ParseSigned(tokenString, signatureAlgorithms(v.signatureAlgorithm))
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

func validateClaimsWithLeeway(actualClaims jwt.Claims, expectedIn []jwt.Expected, leeway time.Duration) error {
	now := time.Now()
	var currentError error
	for _, expected := range expectedIn {
		expectedClaims := expected
		expectedClaims.Time = now

		if actualClaims.Issuer != expectedClaims.Issuer {
			currentError = createOrWrapError(currentError, jwt.ErrInvalidIssuer, actualClaims.Issuer, expectedClaims.Issuer)
			continue
		}

		foundAudience := false
		for _, value := range expectedClaims.AnyAudience {
			if actualClaims.Audience.Contains(value) {
				foundAudience = true
				break
			}
		}
		if !foundAudience {
			currentError = createOrWrapError(
				currentError,
				jwt.ErrInvalidAudience,
				strings.Join(actualClaims.Audience, ","),
				strings.Join(expectedClaims.AnyAudience, ","),
			)
			continue
		}

		if actualClaims.NotBefore != nil && expectedClaims.Time.Add(leeway).Before(actualClaims.NotBefore.Time()) {
			return createOrWrapError(
				currentError,
				jwt.ErrNotValidYet,
				actualClaims.NotBefore.Time().String(),
				expectedClaims.Time.Add(leeway).String(),
			)
		}

		if actualClaims.Expiry != nil && expectedClaims.Time.Add(-leeway).After(actualClaims.Expiry.Time()) {
			return createOrWrapError(
				currentError,
				jwt.ErrExpired,
				actualClaims.Expiry.Time().String(),
				expectedClaims.Time.Add(leeway).String(),
			)
		}

		if actualClaims.IssuedAt != nil && expectedClaims.Time.Add(leeway).Before(actualClaims.IssuedAt.Time()) {
			return createOrWrapError(
				currentError,
				jwt.ErrIssuedInTheFuture,
				actualClaims.IssuedAt.Time().String(),
				expectedClaims.Time.Add(leeway).String(),
			)
		}

		return nil
	}

	return currentError
}

func createOrWrapError(base, current error, actual, expected string) error {
	if base == nil {
		return current
	}

	return errors.Join(base, fmt.Errorf("%v: %s vs %s", current, actual, expected))
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

func signatureAlgorithms(algs ...SignatureAlgorithm) SignatureAlgorithms {
	js := make(SignatureAlgorithms, len(algs))
	for i, alg := range algs {
		js[i] = jose.SignatureAlgorithm(alg)
	}

	return js
}
