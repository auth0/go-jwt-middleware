package josev2

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/pkg/errors"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/auth0/go-jwt-middleware/internal/oidc"
)

// CustomClaims defines any custom data / claims wanted. The validator will
// call the Validate function which is where custom validation logic can be
// defined.
type CustomClaims interface {
	Validate(context.Context) error
}

// UserContext is the struct that will be inserted into the context for the
// user. CustomClaims will be nil unless WithCustomClaims is passed to New.
type UserContext struct {
	CustomClaims CustomClaims
	Claims       jwt.Claims
}

// Option is how options for the validator are setup.
type Option func(*Validator)

// WithAllowedClockSkew is an option which sets up the allowed clock skew for
// the token. Note that in order to use this the expected claims Time field
// MUST not be time.IsZero(). If this option is not used clock skew is not
// allowed.
func WithAllowedClockSkew(skew time.Duration) Option {
	return func(v *Validator) {
		v.allowedClockSkew = skew
	}
}

// WithCustomClaims sets up a function that returns the object CustomClaims are
// unmarshalled into and the object which Validate is called on for custom
// validation. If this option is not used the validator will do nothing for
// custom claims.
func WithCustomClaims(f func() CustomClaims) Option {
	return func(v *Validator) {
		v.customClaims = f
	}
}

// WithExpectedClaims sets up a function that returns the object used to
// validate claims. If this option is not used a default jwt.Expected object is
// used which only validates token time.
func WithExpectedClaims(f func() jwt.Expected) Option {
	return func(v *Validator) {
		v.expectedClaims = f
	}
}

// New sets up a new Validator. With the required keyFunc and
// signatureAlgorithm as well as options.
func New(keyFunc func(context.Context) (interface{}, error),
	signatureAlgorithm jose.SignatureAlgorithm,
	opts ...Option) (*Validator, error) {

	if keyFunc == nil {
		return nil, errors.New("keyFunc is required but was nil")
	}

	v := &Validator{
		allowedClockSkew:   0,
		keyFunc:            keyFunc,
		signatureAlgorithm: signatureAlgorithm,
		customClaims:       nil,
		expectedClaims: func() jwt.Expected {
			return jwt.Expected{
				Time: time.Now(),
			}
		},
	}

	for _, opt := range opts {
		opt(v)
	}

	return v, nil
}

type Validator struct {
	// required options

	// in the past keyFunc might take in a token as a parameter in order to
	// allow the function provider to return a key based on a header kid.
	// With josev2 `jose.JSONWebKeySet` is supported as a return type of
	// this function which hands off the heavy lifting of determining which
	// key to used based on the header `kid` to the josev2 library.
	keyFunc            func(context.Context) (interface{}, error)
	signatureAlgorithm jose.SignatureAlgorithm

	// optional options which we will default if not specified
	expectedClaims   func() jwt.Expected
	allowedClockSkew time.Duration
	customClaims     func() CustomClaims
}

// ValidateToken validates the passed in JWT using the jose v2 package.
func (v *Validator) ValidateToken(ctx context.Context, token string) (interface{}, error) {
	tok, err := jwt.ParseSigned(token)
	if err != nil {
		return nil, fmt.Errorf("could not parse the token: %w", err)
	}

	signatureAlgorithm := string(v.signatureAlgorithm)

	// if jwt.ParseSigned did not error there will always be at least one
	// header in the token
	if signatureAlgorithm != "" && signatureAlgorithm != tok.Headers[0].Algorithm {
		return nil, fmt.Errorf("expected %q signing algorithm but token specified %q", signatureAlgorithm, tok.Headers[0].Algorithm)
	}

	key, err := v.keyFunc(ctx)
	if err != nil {
		return nil, fmt.Errorf("error getting the keys from the key func: %w", err)
	}

	claimDest := []interface{}{&jwt.Claims{}}
	if v.customClaims != nil {
		claimDest = append(claimDest, v.customClaims())
	}

	if err = tok.Claims(key, claimDest...); err != nil {
		return nil, fmt.Errorf("could not get token claims: %w", err)
	}

	userCtx := &UserContext{
		CustomClaims: nil,
		Claims:       *claimDest[0].(*jwt.Claims),
	}

	if err = userCtx.Claims.ValidateWithLeeway(v.expectedClaims(), v.allowedClockSkew); err != nil {
		return nil, fmt.Errorf("expected claims not validated: %w", err)
	}

	if v.customClaims != nil {
		userCtx.CustomClaims = claimDest[1].(CustomClaims)
		if err = userCtx.CustomClaims.Validate(ctx); err != nil {
			return nil, fmt.Errorf("custom claims not validated: %w", err)
		}
	}

	return userCtx, nil
}

// JWKSProvider handles getting JWKS from the specified IssuerURL and exposes
// KeyFunc which adheres to the keyFunc signature that the Validator requires.
// Most likely you will want to use the CachingJWKSProvider as it handles
// getting and caching JWKS which can help reduce request time and potential
// rate limiting from your provider.
type JWKSProvider struct {
	IssuerURL url.URL
}

// NewJWKSProvider builds and returns a new JWKSProvider.
func NewJWKSProvider(issuerURL url.URL) *JWKSProvider {
	return &JWKSProvider{IssuerURL: issuerURL}
}

// KeyFunc adheres to the keyFunc signature that the Validator requires. While
// it returns an interface to adhere to keyFunc, as long as the error is nil
// the type will be *jose.JSONWebKeySet.
func (p *JWKSProvider) KeyFunc(ctx context.Context) (interface{}, error) {
	wkEndpoints, err := oidc.GetWellKnownEndpointsFromIssuerURL(ctx, p.IssuerURL)
	if err != nil {
		return nil, err
	}

	u, err := url.Parse(wkEndpoints.JWKSURI)
	if err != nil {
		return nil, fmt.Errorf("could not parse JWKS URI from well known endpoints: %w", err)
	}

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("could not build request to get JWKS: %w", err)
	}
	req = req.WithContext(ctx)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var jwks jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("could not decode jwks: %w", err)
	}

	return &jwks, nil
}

type cachedJWKS struct {
	jwks      *jose.JSONWebKeySet
	expiresAt time.Time
}

// CachingJWKSProvider handles getting JWKS from the specified IssuerURL and
// caching them for CacheTTL time. It exposes KeyFunc which adheres to the
// keyFunc signature that the Validator requires.
type CachingJWKSProvider struct {
	IssuerURL url.URL
	CacheTTL  time.Duration

	mu    sync.Mutex
	cache map[string]cachedJWKS
}

// NewCachingJWKSProvider builds and returns a new CachingJWKSProvider. If
// cacheTTL is zero then a default value of 1 minute will be used.
func NewCachingJWKSProvider(issuerURL url.URL, cacheTTL time.Duration) *CachingJWKSProvider {
	if cacheTTL == 0 {
		cacheTTL = 1 * time.Minute
	}

	return &CachingJWKSProvider{
		IssuerURL: issuerURL,
		CacheTTL:  cacheTTL,
		cache:     map[string]cachedJWKS{},
	}
}

// KeyFunc adheres to the keyFunc signature that the Validator requires. While
// it returns an interface to adhere to keyFunc, as long as the error is nil
// the type will be *jose.JSONWebKeySet.
func (c *CachingJWKSProvider) KeyFunc(ctx context.Context) (interface{}, error) {
	issuer := c.IssuerURL.Hostname()

	c.mu.Lock()
	defer func() {
		c.mu.Unlock()
	}()

	if cached, ok := c.cache[issuer]; ok {
		if !time.Now().After(cached.expiresAt) {
			return cached.jwks, nil
		}
	}

	p := JWKSProvider{IssuerURL: c.IssuerURL}
	jwks, err := p.KeyFunc(ctx)
	if err != nil {
		return nil, err
	}

	c.cache[issuer] = cachedJWKS{
		jwks:      jwks.(*jose.JSONWebKeySet),
		expiresAt: time.Now().Add(c.CacheTTL),
	}

	return jwks, nil
}
