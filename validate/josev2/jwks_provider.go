package josev2

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
	IssuerURL url.URL
}

// NewJWKSProvider builds and returns a new *JWKSProvider.
func NewJWKSProvider(issuerURL url.URL) *JWKSProvider {
	return &JWKSProvider{IssuerURL: issuerURL}
}

// KeyFunc adheres to the keyFunc signature that the Validator requires.
// While it returns an interface to adhere to keyFunc, as long as the
// error is nil the type will be *jose.JSONWebKeySet.
func (p *JWKSProvider) KeyFunc(ctx context.Context) (interface{}, error) {
	wkEndpoints, err := oidc.GetWellKnownEndpointsFromIssuerURL(ctx, p.IssuerURL)
	if err != nil {
		return nil, err
	}

	jwksURI, err := url.Parse(wkEndpoints.JWKSURI)
	if err != nil {
		return nil, fmt.Errorf("could not parse JWKS URI from well known endpoints: %w", err)
	}

	request, err := http.NewRequest(http.MethodGet, jwksURI.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("could not build request to get JWKS: %w", err)
	}
	request = request.WithContext(ctx)

	response, err := http.DefaultClient.Do(request)
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
	IssuerURL url.URL
	CacheTTL  time.Duration
	mu        sync.Mutex
	cache     map[string]cachedJWKS
}

type cachedJWKS struct {
	jwks      *jose.JSONWebKeySet
	expiresAt time.Time
}

// NewCachingJWKSProvider builds and returns a new CachingJWKSProvider.
// If cacheTTL is zero then a default value of 1 minute will be used.
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

// KeyFunc adheres to the keyFunc signature that the Validator requires.
// While it returns an interface to adhere to keyFunc, as long as the
// error is nil the type will be *jose.JSONWebKeySet.
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

	provider := JWKSProvider{IssuerURL: c.IssuerURL}
	jwks, err := provider.KeyFunc(ctx)
	if err != nil {
		return nil, err
	}

	c.cache[issuer] = cachedJWKS{
		jwks:      jwks.(*jose.JSONWebKeySet),
		expiresAt: time.Now().Add(c.CacheTTL),
	}

	return jwks, nil
}
