package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

func TestHandler(t *testing.T) {
	testCases := []struct {
		name           string
		username       string
		wantStatusCode int
	}{
		{
			name:           "has username",
			username:       "testing",
			wantStatusCode: http.StatusOK,
		},
		{
			name:           "does not have username",
			username:       "",
			wantStatusCode: http.StatusBadRequest,
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			request, err := http.NewRequest(http.MethodGet, "", nil)
			if err != nil {
				t.Fatal(err)
			}

			token := buildJWTForTesting(t, test.username)
			request.Header.Set("Authorization", "Bearer "+token)

			responseRecorder := httptest.NewRecorder()

			mainHandler := setupHandler()
			mainHandler.ServeHTTP(responseRecorder, request)

			if want, got := test.wantStatusCode, responseRecorder.Code; want != got {
				t.Fatalf("wanted status code %d, but got status code %d", want, got)
			}
		})
	}
}

func buildJWTForTesting(t *testing.T, username string) string {
	t.Helper()

	key := jose.SigningKey{
		Algorithm: jose.HS256,
		Key:       signingKey,
	}

	signer, err := jose.NewSigner(key, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatalf("could not build signer: %s", err.Error())
	}

	claims := jwt.Claims{
		Issuer:   issuer,
		Audience: audience,
	}
	customClaims := CustomClaimsExample{
		Username: username,
	}

	token, err := jwt.Signed(signer).Claims(claims).Claims(customClaims).CompactSerialize()
	if err != nil {
		t.Fatalf("could not build token: %s", err.Error())
	}

	return token
}
