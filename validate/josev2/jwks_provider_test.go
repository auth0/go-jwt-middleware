package josev2

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"gopkg.in/square/go-jose.v2"

	"github.com/Hikely/go-jwt-middleware/internal/oidc"
)

func Test_JWKSProvider(t *testing.T) {
	var (
		p                            CachingJWKSProvider
		server                       *httptest.Server
		responseBytes                []byte
		responseStatusCode, reqCount int
		serverURL                    *url.URL
	)

	tests := []struct {
		name string
		main func(t *testing.T)
	}{
		{
			name: "calls out to well known endpoint",
			main: func(t *testing.T) {
				_, jwks := genValidRSAKeyAndJWKS(t)
				var err error
				responseBytes, err = json.Marshal(jwks)
				if !equalErrors(err, "") {
					t.Fatalf("did not want an error, but got %s", err)
				}

				_, err = p.KeyFunc(context.TODO())
				if !equalErrors(err, "") {
					t.Fatalf("did not want an error, but got %s", err)
				}
			},
		},
		{
			name: "errors if it can't decode the jwks",
			main: func(t *testing.T) {
				responseBytes = []byte("<>")
				_, err := p.KeyFunc(context.TODO())

				wantErr := "could not decode jwks: invalid character '<' looking for beginning of value"
				if !equalErrors(err, wantErr) {
					t.Fatalf("wanted err:\n%s\ngot:\n%+v\n", wantErr, err)
				}
			},
		},
		{
			name: "passes back the valid jwks",
			main: func(t *testing.T) {
				_, jwks := genValidRSAKeyAndJWKS(t)
				var err error
				responseBytes, err = json.Marshal(jwks)
				if !equalErrors(err, "") {
					t.Fatalf("did not want an error, but got %s", err)
				}

				p.CacheTTL = time.Minute * 5
				actualJWKS, err := p.KeyFunc(context.TODO())
				if !equalErrors(err, "") {
					t.Fatalf("did not want an error, but got %s", err)
				}

				if want, got := &jwks, actualJWKS; !cmp.Equal(want, got) {
					t.Fatalf("jwks did not match: %s", cmp.Diff(want, got))
				}

				if want, got := &jwks, p.cache[serverURL.Hostname()].jwks; !cmp.Equal(want, got) {
					t.Fatalf("cached jwks did not match: %s", cmp.Diff(want, got))
				}

				expiresAt := p.cache[serverURL.Hostname()].expiresAt
				if !time.Now().Before(expiresAt) {
					t.Fatalf("wanted cache item expiration to be in the future but it was not: %s", expiresAt)
				}
			},
		},
		{
			name: "returns the cached jwks when they are not expired",
			main: func(t *testing.T) {
				_, expectedCachedJWKS := genValidRSAKeyAndJWKS(t)
				p.cache[serverURL.Hostname()] = cachedJWKS{
					jwks:      &expectedCachedJWKS,
					expiresAt: time.Now().Add(1 * time.Minute),
				}

				actualJWKS, err := p.KeyFunc(context.TODO())
				if !equalErrors(err, "") {
					t.Fatalf("did not want an error, but got %s", err)
				}

				if want, got := &expectedCachedJWKS, actualJWKS; !cmp.Equal(want, got) {
					t.Fatalf("cached jwks did not match: %s", cmp.Diff(want, got))
				}

				if reqCount > 0 {
					t.Fatalf("did not want any requests since we should have read from the cache, but we got %d requests", reqCount)
				}
			},
		},
		{
			name: "re-caches the jwks if they have expired",
			main: func(t *testing.T) {
				_, expiredCachedJWKS := genValidRSAKeyAndJWKS(t)
				expiresAt := time.Now().Add(-10 * time.Minute)
				p.cache[server.URL] = cachedJWKS{
					jwks:      &expiredCachedJWKS,
					expiresAt: expiresAt,
				}
				_, jwks := genValidRSAKeyAndJWKS(t)
				var err error
				responseBytes, err = json.Marshal(jwks)
				if !equalErrors(err, "") {
					t.Fatalf("did not want an error, but got %s", err)
				}

				p.CacheTTL = time.Minute * 5
				actualJWKS, err := p.KeyFunc(context.TODO())
				if !equalErrors(err, "") {
					t.Fatalf("did not want an error, but got %s", err)
				}

				if want, got := &jwks, actualJWKS; !cmp.Equal(want, got) {
					t.Fatalf("jwks did not match: %s", cmp.Diff(want, got))
				}

				if want, got := &jwks, p.cache[serverURL.Hostname()].jwks; !cmp.Equal(want, got) {
					t.Fatalf("cached jwks did not match: %s", cmp.Diff(want, got))
				}

				cacheExpiresAt := p.cache[serverURL.Hostname()].expiresAt
				if !time.Now().Before(cacheExpiresAt) {
					t.Fatalf("wanted cache item expiration to be in the future but it was not: %s", cacheExpiresAt)
				}
			},
		},
		{
			name: "only calls the API once when multiple requests come in",
			main: func(t *testing.T) {
				_, jwks := genValidRSAKeyAndJWKS(t)
				var err error
				responseBytes, err = json.Marshal(jwks)
				if !equalErrors(err, "") {
					t.Fatalf("did not want an error, but got %s", err)
				}

				p.CacheTTL = time.Minute * 5

				wg := sync.WaitGroup{}
				for i := 0; i < 50; i++ {
					wg.Add(1)
					go func(t *testing.T) {
						actualJWKS, err := p.KeyFunc(context.TODO())
						if !equalErrors(err, "") {
							t.Errorf("did not want an error, but got %s", err)
						}

						if want, got := &jwks, actualJWKS; !cmp.Equal(want, got) {
							t.Errorf("jwks did not match: %s", cmp.Diff(want, got))
						}

						wg.Done()
					}(t)
				}
				wg.Wait()

				actualJWKS, err := p.KeyFunc(context.TODO())
				if !equalErrors(err, "") {
					t.Fatalf("did not want an error, but got %s", err)
				}

				if want, got := &jwks, actualJWKS; !cmp.Equal(want, got) {
					t.Fatalf("jwks did not match: %s", cmp.Diff(want, got))
				}

				if reqCount != 2 {
					t.Fatalf("only wanted 2 requests (well known and jwks) , but we got %d requests", reqCount)
				}

				if want, got := &jwks, p.cache[serverURL.Hostname()].jwks; !cmp.Equal(want, got) {
					t.Fatalf("cached jwks did not match: %s", cmp.Diff(want, got))
				}

				cacheExpiresAt := p.cache[serverURL.Hostname()].expiresAt
				if !time.Now().Before(cacheExpiresAt) {
					t.Fatalf("wanted cache item expiration to be in the future but it was not: %s", cacheExpiresAt)
				}
			},
		},
	}

	for _, test := range tests {
		var reqCallMutex sync.Mutex

		reqCount = 0
		responseBytes = []byte(`{"kid":""}`)
		responseStatusCode = http.StatusOK
		server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// handle mutex things
			reqCallMutex.Lock()
			defer reqCallMutex.Unlock()
			reqCount++
			w.WriteHeader(responseStatusCode)

			switch r.URL.String() {
			case "/.well-known/openid-configuration":
				wk := oidc.WellKnownEndpoints{JWKSURI: server.URL + "/url_for_jwks"}
				err := json.NewEncoder(w).Encode(wk)
				if !equalErrors(err, "") {
					t.Fatalf("did not want an error, but got %s", err)
				}
			case "/url_for_jwks":
				_, err := w.Write(responseBytes)
				if !equalErrors(err, "") {
					t.Fatalf("did not want an error, but got %s", err)
				}
			default:
				t.Fatalf("do not know how to handle url %s", r.URL.String())
			}
		}))
		defer server.Close()
		serverURL = mustParseURL(server.URL)

		p = CachingJWKSProvider{
			IssuerURL: *serverURL,
			CacheTTL:  0,
			cache:     map[string]cachedJWKS{},
		}

		t.Run(test.name, test.main)
	}
}

func mustParseURL(toParse string) *url.URL {
	parsed, err := url.Parse(toParse)
	if err != nil {
		panic(err)
	}

	return parsed
}

func genValidRSAKeyAndJWKS(t *testing.T) (*rsa.PrivateKey, jose.JSONWebKeySet) {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1653),
	}
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	rawCert, err := x509.CreateCertificate(rand.Reader, ca, ca, &priv.PublicKey, priv)
	if !equalErrors(err, "") {
		t.Fatalf("did not want an error, but got %s", err)
	}

	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key:   priv,
				KeyID: "kid",
				Certificates: []*x509.Certificate{
					{
						Raw: rawCert,
					},
				},
				CertificateThumbprintSHA1:   []uint8{},
				CertificateThumbprintSHA256: []uint8{},
			},
		},
	}
	return priv, jwks
}
