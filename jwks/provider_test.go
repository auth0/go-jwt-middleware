package jwks

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
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"

	"github.com/auth0/go-jwt-middleware/v2/internal/oidc"
)

func Test_JWKSProvider(t *testing.T) {
	var requestCount int32

	expectedJWKS, err := generateJWKS()
	require.NoError(t, err)

	expectedCustomJWKS, err := generateJWKS()
	require.NoError(t, err)

	testServer := setupTestServer(t, expectedJWKS, expectedCustomJWKS, &requestCount)
	defer testServer.Close()

	testServerURL, err := url.Parse(testServer.URL)
	require.NoError(t, err)

	t.Run("It correctly fetches the JWKS after calling the discovery endpoint", func(t *testing.T) {
		provider := NewProvider(testServerURL)
		actualJWKS, err := provider.KeyFunc(context.Background())
		require.NoError(t, err)

		if !cmp.Equal(expectedJWKS, actualJWKS) {
			t.Fatalf("jwks did not match: %s", cmp.Diff(expectedJWKS, actualJWKS))
		}
	})

	t.Run("It skips the discovery if a custom JWKS_URI is provided", func(t *testing.T) {
		customJWKSURI, err := url.Parse(testServer.URL + "/custom/jwks.json")
		require.NoError(t, err)

		provider := NewProvider(testServerURL, WithCustomJWKSURI(customJWKSURI))
		actualJWKS, err := provider.KeyFunc(context.Background())
		require.NoError(t, err)

		if !cmp.Equal(expectedCustomJWKS, actualJWKS) {
			t.Fatalf("jwks did not match: %s", cmp.Diff(expectedCustomJWKS, actualJWKS))
		}
	})

	t.Run("It tells the provider to cancel fetching the JWKS if request is cancelled", func(t *testing.T) {
		ctx := context.Background()
		ctx, cancel := context.WithTimeout(ctx, 0)
		defer cancel()

		provider := NewProvider(testServerURL)
		_, err := provider.KeyFunc(ctx)
		if !strings.Contains(err.Error(), "context deadline exceeded") {
			t.Fatalf("was expecting context deadline to exceed but error is: %v", err)
		}
	})

	t.Run("It re-caches the JWKS if they have expired when using CachingProvider", func(t *testing.T) {
		expiredCachedJWKS, err := generateJWKS()
		require.NoError(t, err)

		provider := NewCachingProvider(testServerURL, 5*time.Minute)
		provider.cache[testServerURL.Hostname()] = cachedJWKS{
			jwks:      expiredCachedJWKS,
			expiresAt: time.Now().Add(-10 * time.Minute),
		}

		actualJWKS, err := provider.KeyFunc(context.Background())
		require.NoError(t, err)

		if !cmp.Equal(expectedJWKS, actualJWKS) {
			t.Fatalf("jwks did not match: %s", cmp.Diff(expectedJWKS, actualJWKS))
		}

		if !cmp.Equal(expectedJWKS, provider.cache[testServerURL.Hostname()].jwks) {
			t.Fatalf("cached jwks did not match: %s", cmp.Diff(expectedJWKS, provider.cache[testServerURL.Hostname()].jwks))
		}

		cacheExpiresAt := provider.cache[testServerURL.Hostname()].expiresAt
		if !time.Now().Before(cacheExpiresAt) {
			t.Fatalf("wanted cache item expiration to be in the future but it was not: %s", cacheExpiresAt)
		}
	})

	t.Run(
		"It only calls the API once when multiple requests come in when using the CachingProvider",
		func(t *testing.T) {
			requestCount = 0

			provider := NewCachingProvider(testServerURL, 5*time.Minute)

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

	t.Run("It sets the caching TTL to 1 if 0 is provided when using the CachingProvider", func(t *testing.T) {
		provider := NewCachingProvider(testServerURL, 0)
		if provider.CacheTTL != time.Minute {
			t.Fatalf("was expecting cache ttl to be 1 minute")
		}
	})

	t.Run(
		"It fails to parse the jwks uri after fetching it from the discovery endpoint if malformed",
		func(t *testing.T) {
			malformedURL, err := url.Parse(testServer.URL+"/malformed")
			require.NoError(t, err)

			provider := NewProvider(malformedURL)
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
			err := json.NewEncoder(w).Encode(wk)
			require.NoError(t, err)
		case "/.well-known/openid-configuration":
			wk := oidc.WellKnownEndpoints{JWKSURI: server.URL + "/.well-known/jwks.json"}
			err := json.NewEncoder(w).Encode(wk)
			require.NoError(t, err)
		case "/.well-known/jwks.json":
			err := json.NewEncoder(w).Encode(expectedJWKS)
			require.NoError(t, err)
		case "/custom/jwks.json":
			err := json.NewEncoder(w).Encode(expectedCustomJWKS)
			require.NoError(t, err)
		default:
			t.Fatalf("was not expecting to handle the following url: %s", r.URL.String())
		}
	})

	return httptest.NewServer(handler)
}
