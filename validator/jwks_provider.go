package validator

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"gopkg.in/square/go-jose.v2"

	"github.com/auth0/go-jwt-middleware/internal/oidc"
)

// JWKSProvider handles getting JWKS from the specified IssuerURL and exposes
// KeyFunc which adheres to the keyFunc signature that the Validator requires.
// Most likely you will want to use the CachingJWKSProvider as it handles
// getting and caching JWKS which can help reduce request time and potential
// rate limiting from your provider.
type JWKSProvider struct {
	IssuerURL     *url.URL // Required.
	CustomJWKSURI *url.URL // Optional.
	Client        *http.Client
}

// ProviderOption is how options for the JWKSProvider are set up.
type ProviderOption func(*JWKSProvider)

// NewJWKSProvider builds and returns a new *JWKSProvider.
func NewJWKSProvider(issuerURL *url.URL, opts ...ProviderOption) *JWKSProvider {
	p := &JWKSProvider{
		IssuerURL: issuerURL,
		Client:    &http.Client{},
	}

	for _, opt := range opts {
		opt(p)
	}

	return p
}

// WithCustomJWKSURI will set a custom JWKS URI on the *JWKSProvider and
// call this directly inside the keyFunc in order to fetch the JWKS,
// skipping the oidc.GetWellKnownEndpointsFromIssuerURL call.
func WithCustomJWKSURI(jwksURI *url.URL) ProviderOption {
	return func(p *JWKSProvider) {
		p.CustomJWKSURI = jwksURI
	}
}

// KeyFunc adheres to the keyFunc signature that the Validator requires.
// While it returns an interface to adhere to keyFunc, as long as the
// error is nil the type will be *jose.JSONWebKeySet.
func (p *JWKSProvider) KeyFunc(ctx context.Context) (interface{}, error) {
	jwksURI := p.CustomJWKSURI
	if jwksURI == nil {
		wkEndpoints, err := oidc.GetWellKnownEndpointsFromIssuerURL(ctx, p.Client, *p.IssuerURL)
		if err != nil {
			return nil, err
		}

		jwksURI, err = url.Parse(wkEndpoints.JWKSURI)
		if err != nil {
			return nil, fmt.Errorf("could not parse JWKS URI from well known endpoints: %w", err)
		}
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("could not build request to get JWKS: %w", err)
	}

	response, err := p.Client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	var jwks jose.JSONWebKeySet
	if err := json.NewDecoder(response.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("could not decode jwks: %w", err)
	}

	return &jwks, nil
}

// CachingJWKSProvider handles getting JWKS from the specified IssuerURL
// and caching them for CacheTTL time. It exposes KeyFunc which adheres
// to the keyFunc signature that the Validator requires.
type CachingJWKSProvider struct {
	*JWKSProvider
	CacheTTL time.Duration
	mu       sync.Mutex
	cache    map[string]cachedJWKS
}

type cachedJWKS struct {
	jwks      *jose.JSONWebKeySet
	expiresAt time.Time
}

// NewCachingJWKSProvider builds and returns a new CachingJWKSProvider.
// If cacheTTL is zero then a default value of 1 minute will be used.
func NewCachingJWKSProvider(issuerURL *url.URL, cacheTTL time.Duration, opts ...ProviderOption) *CachingJWKSProvider {
	if cacheTTL == 0 {
		cacheTTL = 1 * time.Minute
	}

	return &CachingJWKSProvider{
		JWKSProvider: NewJWKSProvider(issuerURL, opts...),
		CacheTTL:     cacheTTL,
		cache:        map[string]cachedJWKS{},
	}
}

// KeyFunc adheres to the keyFunc signature that the Validator requires.
// While it returns an interface to adhere to keyFunc, as long as the
// error is nil the type will be *jose.JSONWebKeySet.
func (c *CachingJWKSProvider) KeyFunc(ctx context.Context) (interface{}, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	issuer := c.IssuerURL.Hostname()

	if cached, ok := c.cache[issuer]; ok {
		if !time.Now().After(cached.expiresAt) {
			return cached.jwks, nil
		}
	}

	jwks, err := c.JWKSProvider.KeyFunc(ctx)
	if err != nil {
		return nil, err
	}

	c.cache[issuer] = cachedJWKS{
		jwks:      jwks.(*jose.JSONWebKeySet),
		expiresAt: time.Now().Add(c.CacheTTL),
	}

	return jwks, nil
}
