package validator

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"gopkg.in/square/go-jose.v2"

	"github.com/auth0/go-jwt-middleware/internal/oidc"
)

func Test_JWKSProvider(t *testing.T) {
	var requestCount int32

	expectedJWKS, err := generateJWKS()
	if err != nil {
		t.Fatalf("did not expect an error but gone one: %v", err)
	}

	expectedCustomJWKS, err := generateJWKS()
	if err != nil {
		t.Fatalf("did not expect an error but gone one: %v", err)
	}

	server := setupTestServer(t, expectedJWKS, expectedCustomJWKS, &requestCount)
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("did not want an error, but got %s", err)
	}

	t.Run("It correctly fetches the JWKS after calling the discovery endpoint", func(t *testing.T) {
		provider := NewJWKSProvider(serverURL)
		actualJWKS, err := provider.KeyFunc(context.Background())
		if err != nil {
			t.Fatalf("did not want an error, but got %s", err)
		}

		if !cmp.Equal(expectedJWKS, actualJWKS) {
			t.Fatalf("jwks did not match: %s", cmp.Diff(expectedJWKS, actualJWKS))
		}
	})

	t.Run("It skips the discovery if a custom JWKS_URI is provided", func(t *testing.T) {
		customJWKSURI, err := url.Parse(server.URL + "/custom/jwks.json")
		if err != nil {
			t.Fatalf("did not want an error, but got %s", err)
		}

		provider := NewJWKSProvider(serverURL, WithCustomJWKSURI(customJWKSURI))
		actualJWKS, err := provider.KeyFunc(context.Background())
		if err != nil {
			t.Fatalf("did not want an error, but got %s", err)
		}

		if !cmp.Equal(expectedCustomJWKS, actualJWKS) {
			t.Fatalf("jwks did not match: %s", cmp.Diff(expectedCustomJWKS, actualJWKS))
		}
	})

	t.Run("It tells the provider to cancel fetching the JWKS if request is cancelled", func(t *testing.T) {
		ctx := context.Background()
		ctx, cancel := context.WithTimeout(ctx, 0)
		defer cancel()

		provider := NewJWKSProvider(serverURL)
		_, err := provider.KeyFunc(ctx)
		if !strings.Contains(err.Error(), "context deadline exceeded") {
			t.Fatalf("was expecting context deadline to exceed but error is: %v", err)
		}
	})

	t.Run("It re-caches the JWKS if they have expired when using CachingJWKSProvider", func(t *testing.T) {
		expiredCachedJWKS, err := generateJWKS()
		if err != nil {
			t.Fatalf("did not expect an error but gone one: %v", err)
		}

		provider := NewCachingJWKSProvider(serverURL, 5*time.Minute)
		provider.cache[serverURL.Hostname()] = cachedJWKS{
			jwks:      expiredCachedJWKS,
			expiresAt: time.Now().Add(-10 * time.Minute),
		}

		actualJWKS, err := provider.KeyFunc(context.Background())
		if err != nil {
			t.Fatalf("did not want an error, but got %s", err)
		}

		if !cmp.Equal(expectedJWKS, actualJWKS) {
			t.Fatalf("jwks did not match: %s", cmp.Diff(expectedJWKS, actualJWKS))
		}

		if !cmp.Equal(expectedJWKS, provider.cache[serverURL.Hostname()].jwks) {
			t.Fatalf("cached jwks did not match: %s", cmp.Diff(expectedJWKS, provider.cache[serverURL.Hostname()].jwks))
		}

		cacheExpiresAt := provider.cache[serverURL.Hostname()].expiresAt
		if !time.Now().Before(cacheExpiresAt) {
			t.Fatalf("wanted cache item expiration to be in the future but it was not: %s", cacheExpiresAt)
		}
	})

	t.Run(
		"It only calls the API once when multiple requests come in when using the CachingJWKSProvider",
		func(t *testing.T) {
			requestCount = 0

			provider := NewCachingJWKSProvider(serverURL, 5*time.Minute)

			var wg sync.WaitGroup
			for i := 0; i < 50; i++ {
				wg.Add(1)
				go func() {
					_, _ = provider.KeyFunc(context.Background())
					wg.Done()
				}()
			}
			wg.Wait()

			if requestCount != 2 {
				t.Fatalf("only wanted 2 requests (well known and jwks) , but we got %d requests", requestCount)
			}
		},
	)

	t.Run("It sets the caching TTL to 1 if 0 is provided when using the CachingJWKSProvider", func(t *testing.T) {
		provider := NewCachingJWKSProvider(serverURL, 0)
		if provider.CacheTTL != time.Minute {
			t.Fatalf("was expecting cache ttl to be 1 minute")
		}
	})

	t.Run(
		"It fails to parse the jwks uri after fetching it from the discovery endpoint if malformed",
		func(t *testing.T) {
			malformedURL, err := url.Parse(server.URL+"/malformed")
			if err != nil {
				t.Fatalf("did not want an error, but got %s", err)
			}

			provider := NewJWKSProvider(malformedURL)
			_, err = provider.KeyFunc(context.Background())
			if !strings.Contains(err.Error(), "could not parse JWKS URI from well known endpoints") {
				t.Fatalf("wanted an error, but got %s", err)
			}
		},
	)
}

func generateJWKS() (*jose.JSONWebKeySet, error) {
	certificate := &x509.Certificate{
		SerialNumber: big.NewInt(1653),
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key")
	}

	rawCertificate, err := x509.CreateCertificate(
		rand.Reader,
		certificate,
		certificate,
		&privateKey.PublicKey,
		privateKey,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate")
	}

	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key:   privateKey,
				KeyID: "kid",
				Certificates: []*x509.Certificate{
					{
						Raw: rawCertificate,
					},
				},
				CertificateThumbprintSHA1:   []uint8{},
				CertificateThumbprintSHA256: []uint8{},
			},
		},
	}

	return &jwks, nil
}

func setupTestServer(
	t *testing.T,
	expectedJWKS *jose.JSONWebKeySet,
	expectedCustomJWKS *jose.JSONWebKeySet,
	requestCount *int32,
) (server *httptest.Server) {
	t.Helper()

	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(requestCount, 1)

		switch r.URL.String() {
		case "/malformed/.well-known/openid-configuration":
			wk := oidc.WellKnownEndpoints{JWKSURI: ":"}
			if err := json.NewEncoder(w).Encode(wk); err != nil {
				t.Fatalf("did not want an error, but got %s", err)
			}
		case "/.well-known/openid-configuration":
			wk := oidc.WellKnownEndpoints{JWKSURI: server.URL + "/.well-known/jwks.json"}
			if err := json.NewEncoder(w).Encode(wk); err != nil {
				t.Fatalf("did not want an error, but got %s", err)
			}
		case "/.well-known/jwks.json":
			if err := json.NewEncoder(w).Encode(expectedJWKS); err != nil {
				t.Fatalf("did not want an error, but got %s", err)
			}
		case "/custom/jwks.json":
			if err := json.NewEncoder(w).Encode(expectedCustomJWKS); err != nil {
				t.Fatalf("did not want an error, but got %s", err)
			}
		default:
			t.Fatalf("was not expecting to handle the following url: %s", r.URL.String())
		}
	})

	return httptest.NewServer(handler)
}
