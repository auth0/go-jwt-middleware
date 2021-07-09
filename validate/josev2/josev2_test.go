package josev2

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/auth0/go-jwt-middleware/internal/oidc"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

type testingCustomClaims struct {
	Subject     string
	ReturnError error
}

func (tcc *testingCustomClaims) Validate(ctx context.Context) error {
	return tcc.ReturnError
}

func equalErrors(actual error, expected string) bool {
	if actual == nil {
		return expected == ""
	}
	return actual.Error() == expected
}

func Test_Validate(t *testing.T) {
	testCases := []struct {
		name               string
		signatureAlgorithm jose.SignatureAlgorithm
		token              string
		keyFuncReturnError error
		customClaims       CustomClaims
		expectedClaims     jwt.Expected
		expectedError      string
		expectedContext    *UserContext
	}{
		{
			name:  "happy path",
			token: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.Rq8IxqeX7eA6GgYxlcHdPFVRNFFZc5rEI3MQTZZbK3I`,
			expectedContext: &UserContext{
				Claims: jwt.Claims{Subject: "1234567890"},
			},
		},
		{
			// we want to test that when it expects RSA but we send
			// HMAC encrypted with the server public key it will
			// error
			name:               "errors on wrong algorithm",
			signatureAlgorithm: jose.PS256,
			token:              `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.XbPfbIHMI6arZ3Y922BhjWgQzWXcXNrz0ogtVhfEd2o`,
			expectedError:      "expected \"PS256\" signing algorithm but token specified \"HS256\"",
		},
		{
			name:          "errors when jwt.ParseSigned errors",
			expectedError: "could not parse the token: square/go-jose: compact JWS format must have three parts",
		},
		{
			name:               "errors when the key func errors",
			token:              `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.XbPfbIHMI6arZ3Y922BhjWgQzWXcXNrz0ogtVhfEd2o`,
			keyFuncReturnError: errors.New("key func error message"),
			expectedError:      "error getting the keys from the key func: key func error message",
		},
		{
			name:          "errors when tok.Claims errors",
			token:         `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.hDyICUnkCrwFJnkJHRSkwMZNSYZ9LI6z2EFJdtwFurA`,
			expectedError: "could not get token claims: square/go-jose: error in cryptographic primitive",
		},
		{
			name:           "errors when expected claims errors",
			token:          `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.XbPfbIHMI6arZ3Y922BhjWgQzWXcXNrz0ogtVhfEd2o`,
			expectedClaims: jwt.Expected{Subject: "wrong subject"},
			expectedError:  "expected claims not validated: square/go-jose/jwt: validation failed, invalid subject claim (sub)",
		},
		{
			name:          "errors when custom claims errors",
			token:         `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.XbPfbIHMI6arZ3Y922BhjWgQzWXcXNrz0ogtVhfEd2o`,
			customClaims:  &testingCustomClaims{ReturnError: errors.New("custom claims error message")},
			expectedError: "custom claims not validated: custom claims error message",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var customClaimsFunc func() CustomClaims = nil
			if testCase.customClaims != nil {
				customClaimsFunc = func() CustomClaims { return testCase.customClaims }
			}

			v, _ := New(func(ctx context.Context) (interface{}, error) { return []byte("secret"), testCase.keyFuncReturnError },
				testCase.signatureAlgorithm,
				WithExpectedClaims(func() jwt.Expected { return testCase.expectedClaims }),
				WithCustomClaims(customClaimsFunc),
			)
			actualContext, err := v.ValidateToken(context.Background(), testCase.token)
			if !equalErrors(err, testCase.expectedError) {
				t.Fatalf("wanted err:\n%s\ngot:\n%+v\n", testCase.expectedError, err)
			}

			if (testCase.expectedContext == nil && actualContext != nil) || (testCase.expectedContext != nil && actualContext == nil) {
				t.Fatalf("wanted user context:\n%+v\ngot:\n%+v\n", testCase.expectedContext, actualContext)
			} else if testCase.expectedContext != nil {
				if diff := cmp.Diff(testCase.expectedContext, actualContext.(*UserContext)); diff != "" {
					t.Errorf("user context mismatch (-want +got):\n%s", diff)
				}

			}

		})
	}
}

func Test_New(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		keyFunc := func(ctx context.Context) (interface{}, error) { return nil, nil }
		customClaims := func() CustomClaims { return nil }

		v, err := New(keyFunc, jose.HS256, WithCustomClaims(customClaims))

		if !equalErrors(err, "") {
			t.Fatalf("wanted err:\n%s\ngot:\n%+v\n", "", err)
		}

		if v.allowedClockSkew != 0 {
			t.Logf("expected allowedClockSkew to be 0 but it was %d", v.allowedClockSkew)
			t.Fail()
		}

		if v.keyFunc == nil {
			t.Log("keyFunc was nil when it should not have been")
			t.Fail()
		}

		if v.signatureAlgorithm != jose.HS256 {
			t.Logf("signatureAlgorithm was %q when it should have been %q", v.signatureAlgorithm, jose.HS256)
			t.Fail()
		}

		if v.customClaims == nil {
			t.Log("customClaims was nil when it should not have been")
			t.Fail()
		}
	})

	t.Run("error on no keyFunc", func(t *testing.T) {
		_, err := New(nil, jose.HS256)

		expectedErr := "keyFunc is required but was nil"
		if !equalErrors(err, expectedErr) {
			t.Fatalf("wanted err:\n%s\ngot:\n%+v\n", expectedErr, err)
		}
	})

}

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

				if want, got := &jwks, actualJWKS; !cmp.Equal(want, got, cmpopts.IgnoreUnexported()) {
					t.Fatalf("jwks did not match: %s", cmp.Diff(want, got, cmpopts.IgnoreUnexported()))
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
