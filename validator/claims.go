package validator

import (
	"context"
)

// ValidatedClaims is the struct that will be inserted into
// the context for the user. CustomClaims will be nil
// unless WithCustomClaims is passed to New.
type ValidatedClaims struct {
	CustomClaims     CustomClaims
	RegisteredClaims RegisteredClaims
}

// RegisteredClaims represents public claim
// values (as specified in RFC 7519).
type RegisteredClaims struct {
	Issuer    string   `json:"iss,omitempty"`
	Subject   string   `json:"sub,omitempty"`
	Audience  []string `json:"aud,omitempty"`
	Expiry    int64    `json:"exp,omitempty"`
	NotBefore int64    `json:"nbf,omitempty"`
	IssuedAt  int64    `json:"iat,omitempty"`
	ID        string   `json:"jti,omitempty"`
}

// CustomClaims defines any custom data / claims wanted.
// The Validator will call the Validate function which
// is where custom validation logic can be defined.
type CustomClaims interface {
	Validate(context.Context) error
}
