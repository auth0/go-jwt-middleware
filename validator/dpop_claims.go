package validator

// DPoPProofClaims represents the claims in a DPoP proof JWT per RFC 9449.
// These claims are extracted from the JWT sent in the DPoP HTTP header.
type DPoPProofClaims struct {
	// JTI is a unique identifier for the DPoP proof JWT.
	// Used for replay protection if nonce tracking is enabled.
	JTI string `json:"jti"`

	// HTM is the HTTP method (GET, POST, PUT, DELETE, etc.).
	// Must match the actual HTTP request method (case-sensitive).
	HTM string `json:"htm"`

	// HTU is the HTTP URI (full URL of the request).
	// Must match the actual request URL (scheme + host + path).
	HTU string `json:"htu"`

	// IAT is the time at which the DPoP proof was created (Unix timestamp).
	// Must be fresh (within configured offset and leeway).
	IAT int64 `json:"iat"`

	// Nonce is an optional server-provided nonce for replay protection.
	Nonce string `json:"nonce,omitempty"`

	// ATH is an optional access token hash (base64url-encoded SHA-256).
	// Used for additional binding in some implementations.
	ATH string `json:"ath,omitempty"`

	// Calculated fields (not in JWT payload, computed during validation)

	// PublicKey is the JWK extracted from the DPoP proof JWT header.
	// Used to verify the proof's signature.
	PublicKey any `json:"-"`

	// PublicKeyThumbprint is the JKT calculated from the PublicKey.
	// This is computed using SHA-256 thumbprint algorithm (RFC 7638).
	// Must match the cnf.jkt from the access token.
	PublicKeyThumbprint string `json:"-"`
}

// GetJTI returns the unique identifier (jti) of the DPoP proof.
// This method implements the core.DPoPProofClaims interface.
func (d *DPoPProofClaims) GetJTI() string {
	return d.JTI
}

// GetHTM returns the HTTP method (htm) from the DPoP proof.
// This method implements the core.DPoPProofClaims interface.
func (d *DPoPProofClaims) GetHTM() string {
	return d.HTM
}

// GetHTU returns the HTTP URI (htu) from the DPoP proof.
// This method implements the core.DPoPProofClaims interface.
func (d *DPoPProofClaims) GetHTU() string {
	return d.HTU
}

// GetIAT returns the issued-at timestamp (iat) from the DPoP proof.
// This method implements the core.DPoPProofClaims interface.
func (d *DPoPProofClaims) GetIAT() int64 {
	return d.IAT
}

// GetPublicKeyThumbprint returns the calculated JKT from the DPoP proof's JWK.
// This method implements the core.DPoPProofClaims interface.
func (d *DPoPProofClaims) GetPublicKeyThumbprint() string {
	return d.PublicKeyThumbprint
}

// GetPublicKey returns the public key from the DPoP proof's JWK.
// This method implements the core.DPoPProofClaims interface.
func (d *DPoPProofClaims) GetPublicKey() any {
	return d.PublicKey
}

// GetATH returns the access token hash (ath) from the DPoP proof.
// This is an optional claim that binds the proof to a specific access token.
// This method implements the core.DPoPProofClaims interface.
func (d *DPoPProofClaims) GetATH() string {
	return d.ATH
}
