package validator

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test_ValidateDPoPProof_Success tests successful DPoP proof validation
func Test_ValidateDPoPProof_Success(t *testing.T) {
	v := &Validator{}
	ctx := context.Background()

	// Generate test key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create JWK from private key
	key, err := jwk.Import(privateKey)
	require.NoError(t, err)

	// Build DPoP proof JWT
	now := time.Now()
	token := jwt.New()
	require.NoError(t, token.Set(jwt.JwtIDKey, "test-jti-123"))
	require.NoError(t, token.Set("htm", "GET"))
	require.NoError(t, token.Set("htu", "https://api.example.com/resource"))
	require.NoError(t, token.Set(jwt.IssuedAtKey, now))

	// Sign with ES256 and embed JWK in header
	headers := jws.NewHeaders()
	headers.Set(jws.TypeKey, "dpop+jwt")
	headers.Set(jws.JWKKey, key)

	signed, err := jwt.Sign(token,
		jwt.WithKey(jwa.ES256(), key, jws.WithProtectedHeaders(headers)),
	)
	require.NoError(t, err)

	proofString := string(signed)

	// Validate the DPoP proof
	claims, err := v.ValidateDPoPProof(ctx, proofString)

	// Assert success
	require.NoError(t, err)
	require.NotNil(t, claims)
	assert.Equal(t, "test-jti-123", claims.JTI)
	assert.Equal(t, "GET", claims.HTM)
	assert.Equal(t, "https://api.example.com/resource", claims.HTU)
	assert.Equal(t, now.Unix(), claims.IAT)
	assert.NotEmpty(t, claims.PublicKeyThumbprint)
	assert.NotNil(t, claims.PublicKey)
}

// Test_ValidateDPoPProof_WithOptionalClaims tests DPoP proof with nonce and ath
func Test_ValidateDPoPProof_WithOptionalClaims(t *testing.T) {
	v := &Validator{}
	ctx := context.Background()

	// Generate test key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	key, err := jwk.Import(privateKey)
	require.NoError(t, err)

	// Build DPoP proof with optional claims
	now := time.Now()
	token := jwt.New()
	require.NoError(t, token.Set(jwt.JwtIDKey, "test-jti"))
	require.NoError(t, token.Set("htm", "POST"))
	require.NoError(t, token.Set("htu", "https://api.example.com/resource"))
	require.NoError(t, token.Set(jwt.IssuedAtKey, now))
	require.NoError(t, token.Set("nonce", "test-nonce-456"))
	require.NoError(t, token.Set("ath", "test-ath-hash"))

	headers := jws.NewHeaders()
	headers.Set(jws.TypeKey, "dpop+jwt")
	headers.Set(jws.JWKKey, key)

	signed, err := jwt.Sign(token,
		jwt.WithKey(jwa.ES256(), key, jws.WithProtectedHeaders(headers)),
	)
	require.NoError(t, err)

	claims, err := v.ValidateDPoPProof(ctx, string(signed))

	require.NoError(t, err)
	require.NotNil(t, claims)
	assert.Equal(t, "test-nonce-456", claims.Nonce)
	assert.Equal(t, "test-ath-hash", claims.ATH)
}

// Test_ValidateDPoPProof_EmptyProof tests validation with empty proof string
func Test_ValidateDPoPProof_EmptyProof(t *testing.T) {
	v := &Validator{}
	ctx := context.Background()

	claims, err := v.ValidateDPoPProof(ctx, "")

	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Contains(t, err.Error(), "DPoP proof string is empty")
}

// Test_ValidateDPoPProof_MalformedJWT tests validation with malformed JWT
func Test_ValidateDPoPProof_MalformedJWT(t *testing.T) {
	v := &Validator{}
	ctx := context.Background()

	testCases := []struct {
		name  string
		proof string
	}{
		{
			name:  "only one part",
			proof: "eyJhbGciOiJFUzI1NiJ9",
		},
		{
			name:  "only two parts",
			proof: "eyJhbGciOiJFUzI1NiJ9.eyJqdGkiOiJ0ZXN0In0",
		},
		{
			name:  "invalid base64",
			proof: "not-valid-base64.also-not-valid.neither-is-this",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			claims, err := v.ValidateDPoPProof(ctx, tc.proof)

			assert.Error(t, err)
			assert.Nil(t, claims)
		})
	}
}

// Test_ValidateDPoPProof_InvalidTypHeader tests validation with wrong typ header
func Test_ValidateDPoPProof_InvalidTypHeader(t *testing.T) {
	v := &Validator{}
	ctx := context.Background()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	key, err := jwk.Import(privateKey)
	require.NoError(t, err)

	token := jwt.New()
	require.NoError(t, token.Set(jwt.JwtIDKey, "test-jti"))
	require.NoError(t, token.Set("htm", "GET"))
	require.NoError(t, token.Set("htu", "https://api.example.com/resource"))
	require.NoError(t, token.Set(jwt.IssuedAtKey, time.Now()))

	// Use wrong typ header
	headers := jws.NewHeaders()
	headers.Set(jws.TypeKey, "JWT") // Should be "dpop+jwt"
	headers.Set(jws.JWKKey, key)

	signed, err := jwt.Sign(token,
		jwt.WithKey(jwa.ES256(), key, jws.WithProtectedHeaders(headers)),
	)
	require.NoError(t, err)

	claims, err := v.ValidateDPoPProof(ctx, string(signed))

	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Contains(t, err.Error(), "invalid DPoP proof typ header")
	assert.Contains(t, err.Error(), "expected \"dpop+jwt\"")
}

// Test_ValidateDPoPProof_MissingJWK tests validation without JWK in header
func Test_ValidateDPoPProof_MissingJWK(t *testing.T) {
	v := &Validator{}
	ctx := context.Background()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	key, err := jwk.Import(privateKey)
	require.NoError(t, err)

	token := jwt.New()
	require.NoError(t, token.Set(jwt.JwtIDKey, "test-jti"))
	require.NoError(t, token.Set("htm", "GET"))
	require.NoError(t, token.Set("htu", "https://api.example.com/resource"))
	require.NoError(t, token.Set(jwt.IssuedAtKey, time.Now()))

	// Sign without JWK in header
	headers := jws.NewHeaders()
	headers.Set(jws.TypeKey, "dpop+jwt")
	// Missing "jwk" field intentionally

	signed, err := jwt.Sign(token,
		jwt.WithKey(jwa.ES256(), key, jws.WithProtectedHeaders(headers)),
	)
	require.NoError(t, err)

	claims, err := v.ValidateDPoPProof(ctx, string(signed))

	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Contains(t, err.Error(), "missing required jwk field")
}

// Test_ValidateDPoPProof_MissingRequiredClaims tests validation with missing claims
func Test_ValidateDPoPProof_MissingRequiredClaims(t *testing.T) {
	v := &Validator{}
	ctx := context.Background()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	key, err := jwk.Import(privateKey)
	require.NoError(t, err)

	testCases := []struct {
		name          string
		setupToken    func(jwt.Token)
		expectedError string
	}{
		{
			name: "missing jti",
			setupToken: func(token jwt.Token) {
				token.Set("htm", "GET")
				token.Set("htu", "https://api.example.com/resource")
				token.Set(jwt.IssuedAtKey, time.Now())
			},
			expectedError: "missing required jti claim",
		},
		{
			name: "missing htm",
			setupToken: func(token jwt.Token) {
				token.Set(jwt.JwtIDKey, "test-jti")
				token.Set("htu", "https://api.example.com/resource")
				token.Set(jwt.IssuedAtKey, time.Now())
			},
			expectedError: "missing required htm claim",
		},
		{
			name: "missing htu",
			setupToken: func(token jwt.Token) {
				token.Set(jwt.JwtIDKey, "test-jti")
				token.Set("htm", "GET")
				token.Set(jwt.IssuedAtKey, time.Now())
			},
			expectedError: "missing required htu claim",
		},
		{
			name: "missing iat",
			setupToken: func(token jwt.Token) {
				token.Set(jwt.JwtIDKey, "test-jti")
				token.Set("htm", "GET")
				token.Set("htu", "https://api.example.com/resource")
			},
			expectedError: "missing required iat claim",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			token := jwt.New()
			tc.setupToken(token)

			headers := jws.NewHeaders()
			headers.Set(jws.TypeKey, "dpop+jwt")
			headers.Set(jws.JWKKey, key)

			signed, err := jwt.Sign(token,
				jwt.WithKey(jwa.ES256(), key, jws.WithProtectedHeaders(headers)),
			)
			require.NoError(t, err)

			claims, err := v.ValidateDPoPProof(ctx, string(signed))

			assert.Error(t, err)
			assert.Nil(t, claims)
			assert.Contains(t, err.Error(), tc.expectedError)
		})
	}
}

// Test_ValidateDPoPProof_InvalidSignature tests validation with tampered proof
func Test_ValidateDPoPProof_InvalidSignature(t *testing.T) {
	v := &Validator{}
	ctx := context.Background()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	key, err := jwk.Import(privateKey)
	require.NoError(t, err)

	token := jwt.New()
	require.NoError(t, token.Set(jwt.JwtIDKey, "test-jti"))
	require.NoError(t, token.Set("htm", "GET"))
	require.NoError(t, token.Set("htu", "https://api.example.com/resource"))
	require.NoError(t, token.Set(jwt.IssuedAtKey, time.Now()))

	headers := jws.NewHeaders()
	headers.Set(jws.TypeKey, "dpop+jwt")
	headers.Set(jws.JWKKey, key)

	signed, err := jwt.Sign(token,
		jwt.WithKey(jwa.ES256(), key, jws.WithProtectedHeaders(headers)),
	)
	require.NoError(t, err)

	// Tamper with the signature - completely replace it with an invalid one
	proofString := string(signed)
	parts := strings.Split(proofString, ".")
	require.Len(t, parts, 3)

	// Replace signature with obviously invalid data
	tamperedProof := parts[0] + "." + parts[1] + ".INVALID_SIGNATURE"

	_, err = v.ValidateDPoPProof(ctx, tamperedProof)

	// Should fail because signature is invalid
	// The test should catch either a signature validation error or a malformed JWT error
	assert.Error(t, err)
}

// Test_ValidateDPoPProof_DifferentAlgorithms tests various signature algorithms
func Test_ValidateDPoPProof_DifferentAlgorithms(t *testing.T) {
	v := &Validator{}
	ctx := context.Background()

	testCases := []struct {
		name      string
		algorithm jwa.SignatureAlgorithm
		keyGen    func() (any, error)
	}{
		{
			name:      "ES256",
			algorithm: jwa.ES256(),
			keyGen: func() (any, error) {
				return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			},
		},
		{
			name:      "ES384",
			algorithm: jwa.ES384(),
			keyGen: func() (any, error) {
				return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
			},
		},
		{
			name:      "RS256",
			algorithm: jwa.RS256(),
			keyGen: func() (any, error) {
				return rsa.GenerateKey(rand.Reader, 2048)
			},
		},
		{
			name:      "PS256",
			algorithm: jwa.PS256(),
			keyGen: func() (any, error) {
				return rsa.GenerateKey(rand.Reader, 2048)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			privateKey, err := tc.keyGen()
			require.NoError(t, err)

			key, err := jwk.Import(privateKey)
			require.NoError(t, err)

			token := jwt.New()
			require.NoError(t, token.Set(jwt.JwtIDKey, "test-jti"))
			require.NoError(t, token.Set("htm", "GET"))
			require.NoError(t, token.Set("htu", "https://api.example.com/resource"))
			require.NoError(t, token.Set(jwt.IssuedAtKey, time.Now()))

			headers := jws.NewHeaders()
			headers.Set(jws.TypeKey, "dpop+jwt")
			headers.Set(jws.JWKKey, key)

			signed, err := jwt.Sign(token,
				jwt.WithKey(tc.algorithm, key, jws.WithProtectedHeaders(headers)),
			)
			require.NoError(t, err)

			claims, err := v.ValidateDPoPProof(ctx, string(signed))

			assert.NoError(t, err)
			assert.NotNil(t, claims)
			assert.Equal(t, "test-jti", claims.JTI)
			assert.NotEmpty(t, claims.PublicKeyThumbprint)
		})
	}
}

// Test_calculateJKT tests JKT calculation for different key types
func Test_calculateJKT(t *testing.T) {
	testCases := []struct {
		name   string
		keyGen func() (any, error)
	}{
		{
			name: "ECDSA P-256",
			keyGen: func() (any, error) {
				return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			},
		},
		{
			name: "ECDSA P-384",
			keyGen: func() (any, error) {
				return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
			},
		},
		{
			name: "RSA 2048",
			keyGen: func() (any, error) {
				return rsa.GenerateKey(rand.Reader, 2048)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			privateKey, err := tc.keyGen()
			require.NoError(t, err)

			key, err := jwk.Import(privateKey)
			require.NoError(t, err)

			jkt, err := calculateJKT(key)

			require.NoError(t, err)
			assert.NotEmpty(t, jkt)

			// JKT should be base64url encoded (no padding)
			assert.NotContains(t, jkt, "=")

			// Should be able to decode it
			decoded, err := base64.RawURLEncoding.DecodeString(jkt)
			require.NoError(t, err)

			// SHA-256 hash is 32 bytes
			assert.Len(t, decoded, 32)

			// Calculate again to ensure determinism
			jkt2, err := calculateJKT(key)
			require.NoError(t, err)
			assert.Equal(t, jkt, jkt2, "JKT calculation should be deterministic")
		})
	}
}

// Test_calculateJKT_MatchesSpec tests that JKT calculation matches RFC 7638
func Test_calculateJKT_MatchesSpec(t *testing.T) {
	// Use a known test vector (you can create one with a specific key)
	// For now, just verify the algorithm works consistently
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	key, err := jwk.Import(privateKey)
	require.NoError(t, err)

	// Calculate JKT
	jkt, err := calculateJKT(key)
	require.NoError(t, err)

	// Verify against jwx library's own thumbprint calculation
	thumbprint, err := key.Thumbprint(crypto.SHA256)
	require.NoError(t, err)

	expectedJKT := base64.RawURLEncoding.EncodeToString(thumbprint)
	assert.Equal(t, expectedJKT, jkt)
}

// Test_extractConfirmationClaim tests cnf claim extraction from access tokens
func Test_extractConfirmationClaim(t *testing.T) {
	v := &Validator{}

	t.Run("extract cnf claim successfully", func(t *testing.T) {
		// Create a token with cnf claim
		payload := map[string]any{
			"iss": "https://issuer.example.com",
			"sub": "user123",
			"aud": "https://api.example.com",
			"exp": time.Now().Add(time.Hour).Unix(),
			"iat": time.Now().Unix(),
			"cnf": map[string]any{
				"jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I",
			},
		}

		payloadJSON, err := json.Marshal(payload)
		require.NoError(t, err)

		// Build a fake JWT (header.payload.signature)
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
		payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
		signature := base64.RawURLEncoding.EncodeToString([]byte("fake-signature"))

		tokenString := header + "." + payloadB64 + "." + signature

		cnf, err := v.extractConfirmationClaim(tokenString)

		require.NoError(t, err)
		require.NotNil(t, cnf)
		assert.Equal(t, "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I", cnf.JKT)
	})

	t.Run("return nil when cnf claim not present", func(t *testing.T) {
		// Create a token WITHOUT cnf claim
		payload := map[string]any{
			"iss": "https://issuer.example.com",
			"sub": "user123",
			"aud": "https://api.example.com",
			"exp": time.Now().Add(time.Hour).Unix(),
			"iat": time.Now().Unix(),
		}

		payloadJSON, err := json.Marshal(payload)
		require.NoError(t, err)

		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
		payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
		signature := base64.RawURLEncoding.EncodeToString([]byte("fake-signature"))

		tokenString := header + "." + payloadB64 + "." + signature

		cnf, err := v.extractConfirmationClaim(tokenString)

		require.NoError(t, err)
		assert.Nil(t, cnf, "cnf should be nil for Bearer tokens")
	})

	t.Run("error on malformed JWT", func(t *testing.T) {
		cnf, err := v.extractConfirmationClaim("invalid-jwt")

		assert.Error(t, err)
		assert.Nil(t, cnf)
		assert.Contains(t, err.Error(), "invalid JWT format")
	})

	t.Run("error on invalid base64", func(t *testing.T) {
		cnf, err := v.extractConfirmationClaim("header.not-valid-base64.signature")

		assert.Error(t, err)
		assert.Nil(t, cnf)
	})
}

// Test_ValidateDPoPProof_InvalidHeaderJSON tests validation with malformed header JSON
func Test_ValidateDPoPProof_InvalidHeaderJSON(t *testing.T) {
	v := &Validator{}
	ctx := context.Background()

	// Create a JWT with invalid JSON in header (missing closing brace)
	invalidHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"dpop+jwt"`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"jti":"test","htm":"GET","htu":"https://api.example.com","iat":1234567890}`))
	signature := base64.RawURLEncoding.EncodeToString([]byte("fake-sig"))

	proofString := invalidHeader + "." + payload + "." + signature

	claims, err := v.ValidateDPoPProof(ctx, proofString)

	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Contains(t, err.Error(), "failed to unmarshal DPoP proof header")
}

// Test_ValidateDPoPProof_InvalidJWK tests validation with malformed JWK
func Test_ValidateDPoPProof_InvalidJWK(t *testing.T) {
	v := &Validator{}
	ctx := context.Background()

	// Create a JWT header with invalid JWK
	headerWithInvalidJWK := map[string]any{
		"alg": "ES256",
		"typ": "dpop+jwt",
		"jwk": map[string]any{
			"kty": "INVALID_KEY_TYPE", // Invalid key type
			"crv": "P-256",
		},
	}

	headerJSON, _ := json.Marshal(headerWithInvalidJWK)
	header := base64.RawURLEncoding.EncodeToString(headerJSON)
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"jti":"test","htm":"GET","htu":"https://api.example.com","iat":1234567890}`))
	signature := base64.RawURLEncoding.EncodeToString([]byte("fake-sig"))

	proofString := header + "." + payload + "." + signature

	claims, err := v.ValidateDPoPProof(ctx, proofString)

	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Contains(t, err.Error(), "failed to parse JWK from DPoP proof header")
}

// Test_ValidateDPoPProof_UnsupportedAlgorithm tests validation with unsupported algorithm
func Test_ValidateDPoPProof_UnsupportedAlgorithm(t *testing.T) {
	v := &Validator{}
	ctx := context.Background()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	key, err := jwk.Import(privateKey)
	require.NoError(t, err)

	// Create a JWT header with unsupported algorithm
	headerWithBadAlg := map[string]any{
		"alg": "UNSUPPORTED_ALG",
		"typ": "dpop+jwt",
		"jwk": key,
	}

	headerJSON, _ := json.Marshal(headerWithBadAlg)
	header := base64.RawURLEncoding.EncodeToString(headerJSON)
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"jti":"test","htm":"GET","htu":"https://api.example.com","iat":1234567890}`))
	signature := base64.RawURLEncoding.EncodeToString([]byte("fake-sig"))

	proofString := header + "." + payload + "." + signature

	claims, err := v.ValidateDPoPProof(ctx, proofString)

	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Contains(t, err.Error(), "unsupported DPoP proof algorithm")
}

// Test_extractDPoPClaims_InvalidPayloadJSON tests extraction with malformed payload
func Test_extractDPoPClaims_InvalidPayloadJSON(t *testing.T) {
	v := &Validator{}

	// Create a JWT with invalid JSON in payload
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"dpop+jwt"}`))
	invalidPayload := base64.RawURLEncoding.EncodeToString([]byte(`{"jti":"test","htm":"GET"`)) // Missing closing brace
	signature := base64.RawURLEncoding.EncodeToString([]byte("fake-sig"))

	proofString := header + "." + invalidPayload + "." + signature

	claims, err := v.extractDPoPClaims(proofString)

	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Contains(t, err.Error(), "failed to unmarshal DPoP proof claims")
}

// Test_extractConfirmationClaim_InvalidPayloadJSON tests extraction with malformed payload
func Test_extractConfirmationClaim_InvalidPayloadJSON(t *testing.T) {
	v := &Validator{}

	// Create a JWT with invalid JSON in payload
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	invalidPayload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"test","sub":`)) // Truncated JSON
	signature := base64.RawURLEncoding.EncodeToString([]byte("fake-sig"))

	tokenString := header + "." + invalidPayload + "." + signature

	cnf, err := v.extractConfirmationClaim(tokenString)

	assert.Error(t, err)
	assert.Nil(t, cnf)
	assert.Contains(t, err.Error(), "failed to unmarshal payload")
}

// Test_extractDPoPClaims_InvalidBase64Payload tests extraction with invalid base64 in payload
func Test_extractDPoPClaims_InvalidBase64Payload(t *testing.T) {
	v := &Validator{}

	// Create a JWT with invalid base64 in payload (contains invalid characters)
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"dpop+jwt"}`))
	invalidPayload := "!!!invalid-base64!!!" // Invalid base64 characters
	signature := base64.RawURLEncoding.EncodeToString([]byte("fake-sig"))

	proofString := header + "." + invalidPayload + "." + signature

	claims, err := v.extractDPoPClaims(proofString)

	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Contains(t, err.Error(), "failed to decode DPoP proof payload")
}

// Test_extractConfirmationClaim_InvalidBase64Payload tests extraction with invalid base64
func Test_extractConfirmationClaim_InvalidBase64Payload(t *testing.T) {
	v := &Validator{}

	// Create a JWT with invalid base64 in payload
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	invalidPayload := "!!!invalid-base64!!!"
	signature := base64.RawURLEncoding.EncodeToString([]byte("fake-sig"))

	tokenString := header + "." + invalidPayload + "." + signature

	cnf, err := v.extractConfirmationClaim(tokenString)

	assert.Error(t, err)
	assert.Nil(t, cnf)
	assert.Contains(t, err.Error(), "failed to decode JWT payload")
}

// Test_calculateJKT_EdgeCases tests edge cases for calculateJKT
func Test_calculateJKT_EdgeCases(t *testing.T) {
	t.Run("valid ecdsa public key", func(t *testing.T) {
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		pubKey := privKey.PublicKey

		dpopJWK, err := jwk.Import(pubKey)
		require.NoError(t, err)
		err = dpopJWK.Set(jwk.AlgorithmKey, jwa.ES256())
		require.NoError(t, err)

		thumbprint, err := calculateJKT(dpopJWK)

		require.NoError(t, err)
		assert.NotEmpty(t, thumbprint)
	})

	t.Run("valid rsa public key", func(t *testing.T) {
		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		pubKey := privKey.PublicKey

		dpopJWK, err := jwk.Import(pubKey)
		require.NoError(t, err)

		thumbprint, err := calculateJKT(dpopJWK)

		require.NoError(t, err)
		assert.NotEmpty(t, thumbprint)
	})
}
