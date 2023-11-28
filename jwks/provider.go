package jwks

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"golang.org/x/sync/semaphore"
	"gopkg.in/go-jose/go-jose.v2"

	"github.com/auth0/go-jwt-middleware/v2/internal/oidc"
)

// Provider handles getting JWKS from the specified IssuerURL and exposes
// KeyFunc which adheres to the keyFunc signature that the Validator requires.
// Most likely you will want to use the CachingProvider as it handles
// getting and caching JWKS which can help reduce request time and potential
// rate limiting from your provider.
type Provider struct {
	IssuerURL     *url.URL // Required.
	CustomJWKSURI *url.URL // Optional.
	Client        *http.Client
}

// ProviderOption is how options for the Provider are set up.
type ProviderOption func(*Provider)

// NewProvider builds and returns a new *Provider.
func NewProvider(issuerURL *url.URL, opts ...ProviderOption) *Provider {
	p := &Provider{
		IssuerURL: issuerURL,
		Client:    &http.Client{},
	}

	for _, opt := range opts {
		opt(p)
	}

	return p
}

// WithCustomJWKSURI will set a custom JWKS URI on the *Provider and
// call this directly inside the keyFunc in order to fetch the JWKS,
// skipping the oidc.GetWellKnownEndpointsFromIssuerURL call.
func WithCustomJWKSURI(jwksURI *url.URL) ProviderOption {
	return func(p *Provider) {
		p.CustomJWKSURI = jwksURI
	}
}

// WithCustomClient will set a custom *http.Client on the *Provider
func WithCustomClient(c *http.Client) ProviderOption {
	return func(p *Provider) {
		p.Client = c
	}
}

// KeyFunc adheres to the keyFunc signature that the Validator requires.
// While it returns an interface to adhere to keyFunc, as long as the
// error is nil the type will be *jose.JSONWebKeySet.
func (p *Provider) KeyFunc(ctx context.Context) (interface{}, error) {
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

// CachingProvider handles getting JWKS from the specified IssuerURL
// and caching them for CacheTTL time. It exposes KeyFunc which adheres
// to the keyFunc signature that the Validator requires.
// When the CacheTTL value has been reached, a JWKS refresh will be triggered
// in the background and the existing cached JWKS will be returned until the
// JWKS cache is updated, or if the request errors then it will be evicted from
// the cache.
type CachingProvider struct {
	*Provider
	CacheTTL time.Duration
	mu       sync.RWMutex
	cache    map[string]cachedJWKS
	sem      semaphore.Weighted
}

type cachedJWKS struct {
	jwks      *jose.JSONWebKeySet
	expiresAt time.Time
}

// NewCachingProvider builds and returns a new CachingProvider.
// If cacheTTL is zero then a default value of 1 minute will be used.
func NewCachingProvider(issuerURL *url.URL, cacheTTL time.Duration, opts ...ProviderOption) *CachingProvider {
	if cacheTTL == 0 {
		cacheTTL = 1 * time.Minute
	}

	return &CachingProvider{
		Provider: NewProvider(issuerURL, opts...),
		CacheTTL: cacheTTL,
		cache:    map[string]cachedJWKS{},
		sem:      *semaphore.NewWeighted(1),
	}
}

// KeyFunc adheres to the keyFunc signature that the Validator requires.
// While it returns an interface to adhere to keyFunc, as long as the
// error is nil the type will be *jose.JSONWebKeySet.
func (c *CachingProvider) KeyFunc(ctx context.Context) (interface{}, error) {
	c.mu.RLock()

	issuer := c.IssuerURL.Hostname()

	if cached, ok := c.cache[issuer]; ok {
		if time.Now().After(cached.expiresAt) && c.sem.TryAcquire(1) {
			go func() {
				defer c.sem.Release(1)
				refreshCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				_, err := c.refreshKey(refreshCtx, issuer)

				if err != nil {
					c.mu.Lock()
					delete(c.cache, issuer)
					c.mu.Unlock()
				}
			}()
		}
		c.mu.RUnlock()
		return cached.jwks, nil
	}

	c.mu.RUnlock()
	return c.refreshKey(ctx, issuer)
}

func (c *CachingProvider) refreshKey(ctx context.Context, issuer string) (interface{}, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	jwks, err := c.Provider.KeyFunc(ctx)
	if err != nil {
		return nil, err
	}

	c.cache[issuer] = cachedJWKS{
		jwks:      jwks.(*jose.JSONWebKeySet),
		expiresAt: time.Now().Add(c.CacheTTL),
	}

	return jwks, nil
}
