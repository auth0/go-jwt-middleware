package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"gopkg.in/go-jose/go-jose.v2"
	"gopkg.in/go-jose/go-jose.v2/jwt"
)

func TestHandler(t *testing.T) {
	testCases := []struct {
		name           string
		subject        string
		wantStatusCode int
	}{
		{
			name:           "has subject",
			subject:        "testing",
			wantStatusCode: http.StatusOK,
		},
		{
			name:           "does not have subject",
			subject:        "",
			wantStatusCode: http.StatusBadRequest,
		},
	}

	jwk := generateJWK(t)

	testServer := setupTestServer(t, jwk)
	defer testServer.Close()

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			request, err := http.NewRequest(http.MethodGet, "", nil)
			if err != nil {
				t.Fatal(err)
			}

			token := buildJWTForTesting(t, jwk, testServer.URL, test.subject, []string{"my-audience"})
			request.Header.Set("Authorization", "Bearer "+token)

			responseRecorder := httptest.NewRecorder()

			mainHandler := setupHandler(testServer.URL, []string{"my-audience"})
			mainHandler.ServeHTTP(responseRecorder, request)

			if want, got := test.wantStatusCode, responseRecorder.Code; want != got {
				t.Fatalf("wanted status code %d, but got status code %d", want, got)
			}
		})
	}
}

func generateJWK(t *testing.T) *jose.JSONWebKey {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal("failed to generate private key")
	}

	return &jose.JSONWebKey{
		Key:       privateKey,
		KeyID:     "kid",
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}
}

func setupTestServer(t *testing.T, jwk *jose.JSONWebKey) (server *httptest.Server) {
	t.Helper()

	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.String() {
		case "/.well-known/openid-configuration":
			wk := struct {
				Issuer  string `json:"issuer"`
				JWKSURI string `json:"jwks_uri"`
			}{
				Issuer:  server.URL,
				JWKSURI: server.URL + "/.well-known/jwks.json",
			}
			if err := json.NewEncoder(w).Encode(wk); err != nil {
				t.Fatal(err)
			}
		case "/.well-known/jwks.json":
			jwks := jose.JSONWebKeySet{
				Keys: []jose.JSONWebKey{jwk.Public()},
			}
			jsonData, err := json.Marshal(jwks)
			if err != nil {
				t.Fatal(err)
			}
			w.Header().Set("Content-Type", "application/json")
			if _, err := w.Write(jsonData); err != nil {
				t.Fatal(err)
			}
		default:
			t.Fatalf("was not expecting to handle the following url: %s", r.URL.String())
		}
	})

	return httptest.NewServer(handler)
}

func buildJWTForTesting(t *testing.T, jwk *jose.JSONWebKey, issuer, subject string, audience []string) string {
	t.Helper()

	key := jose.SigningKey{
		Algorithm: jose.SignatureAlgorithm(jwk.Algorithm),
		Key:       jwk,
	}

	signer, err := jose.NewSigner(key, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatalf("could not build signer: %s", err.Error())
	}

	claims := jwt.Claims{
		Issuer:   issuer,
		Audience: audience,
		Subject:  subject,
		IssuedAt: jwt.NewNumericDate(time.Now()),
		Expiry:   jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
	}

	token, err := jwt.Signed(signer).Claims(claims).CompactSerialize()
	if err != nil {
		t.Fatalf("could not build token: %s", err.Error())
	}

	return token
}
