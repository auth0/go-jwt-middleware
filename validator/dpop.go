package validator

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// DPoP header type constant per RFC 9449
const dpopTyp = "dpop+jwt"

// ValidateDPoPProof validates a DPoP proof JWT and returns the extracted claims.
// It verifies the JWT signature using the embedded JWK and calculates the JKT.
//
// This method performs the following validations per RFC 9449:
//   - Parses the DPoP proof JWT
//   - Verifies the typ header is "dpop+jwt"
//   - Extracts the JWK from the JWT header
//   - Verifies the JWT signature using the embedded JWK
//   - Extracts required claims (jti, htm, htu, iat)
//   - Calculates the JKT (JWK thumbprint) using SHA-256
//
// The method does NOT validate:
//   - htm matches HTTP method (done in core)
//   - htu matches request URL (done in core)
//   - iat freshness (done in core)
//   - JKT matches cnf.jkt from access token (done in core)
//
// This separation ensures the validator remains a pure JWT validation library
// with no knowledge of HTTP requests or transport concerns.
func (v *Validator) ValidateDPoPProof(ctx context.Context, proofString string) (*DPoPProofClaims, error) {
	if proofString == "" {
		return nil, errors.New("DPoP proof string is empty")
	}

	// Step 1: Parse the JWT structure without validation to extract header
	parts := strings.Split(proofString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid DPoP proof format: expected 3 parts, got %d", len(parts))
	}

	// Step 2: Decode and validate the header
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode DPoP proof header: %w", err)
	}

	var header struct {
		Typ string          `json:"typ"`
		Alg string          `json:"alg"`
		JWK json.RawMessage `json:"jwk"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("failed to unmarshal DPoP proof header: %w", err)
	}

	// Step 3: Validate typ header is "dpop+jwt" per RFC 9449
	if header.Typ != dpopTyp {
		return nil, fmt.Errorf("invalid DPoP proof typ header: expected %q, got %q", dpopTyp, header.Typ)
	}

	// Step 4: Validate JWK is present
	if len(header.JWK) == 0 {
		return nil, errors.New("DPoP proof header missing required jwk field")
	}

	// Step 5: Parse the JWK from the header
	publicKey, err := jwk.ParseKey(header.JWK)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWK from DPoP proof header: %w", err)
	}

	// Step 6: Validate the algorithm is allowed
	algorithm := SignatureAlgorithm(header.Alg)
	if !allowedSigningAlgorithms[algorithm] {
		return nil, fmt.Errorf("unsupported DPoP proof algorithm: %s", header.Alg)
	}

	// Step 7: Convert algorithm to jwx type
	jwxAlg, err := stringToJWXAlgorithm(header.Alg)
	if err != nil {
		return nil, fmt.Errorf("failed to convert algorithm: %w", err)
	}

	// Step 8: Parse and verify the JWT signature using the embedded JWK
	token, err := jwt.ParseString(proofString,
		jwt.WithKey(jwxAlg, publicKey),
		jwt.WithValidate(false), // We'll validate claims manually
	)
	if err != nil {
		return nil, fmt.Errorf("failed to parse and verify DPoP proof signature: %w", err)
	}

	// Step 9: Extract required claims from the token
	jti, _ := token.JwtID()
	if jti == "" {
		return nil, errors.New("DPoP proof missing required jti claim")
	}

	issuedAtTime, _ := token.IssuedAt()
	if issuedAtTime.IsZero() {
		return nil, errors.New("DPoP proof missing required iat claim")
	}
	issuedAt := issuedAtTime.Unix()

	// Step 10: Extract DPoP-specific claims from the payload
	dpopClaims, err := v.extractDPoPClaims(proofString)
	if err != nil {
		return nil, err
	}

	// Step 11: Validate required DPoP claims
	if dpopClaims.HTM == "" {
		return nil, errors.New("DPoP proof missing required htm claim")
	}
	if dpopClaims.HTU == "" {
		return nil, errors.New("DPoP proof missing required htu claim")
	}

	// Step 12: Calculate the JKT (JWK thumbprint) using SHA-256 per RFC 7638
	jkt, err := calculateJKT(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate JKT from DPoP proof JWK: %w", err)
	}

	// Step 13: Build the complete DPoPProofClaims with calculated fields
	dpopClaims.JTI = jti
	dpopClaims.IAT = issuedAt
	dpopClaims.PublicKey = publicKey
	dpopClaims.PublicKeyThumbprint = jkt

	return dpopClaims, nil
}

// extractDPoPClaims extracts DPoP-specific claims from the JWT payload.
func (v *Validator) extractDPoPClaims(proofString string) (*DPoPProofClaims, error) {
	// JWT format: header.payload.signature
	parts := strings.Split(proofString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	// Decode the payload using base64url encoding
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode DPoP proof payload: %w", err)
	}

	// Unmarshal JSON payload into DPoPProofClaims struct
	var claims DPoPProofClaims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal DPoP proof claims: %w", err)
	}

	return &claims, nil
}

// calculateJKT computes the JWK thumbprint using SHA-256 per RFC 7638.
// The thumbprint is base64url-encoded without padding.
func calculateJKT(key jwk.Key) (string, error) {
	// Use the jwx library's built-in thumbprint calculation
	// This implements RFC 7638 correctly for all key types
	thumbprint, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("failed to compute JWK thumbprint: %w", err)
	}

	// Encode as base64url without padding per RFC 7638
	jkt := base64.RawURLEncoding.EncodeToString(thumbprint)
	return jkt, nil
}
