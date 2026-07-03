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

	// ConfirmationClaim contains the cnf claim for DPoP binding (RFC 7800, RFC 9449).
	// This field will be nil for Bearer tokens and populated for DPoP tokens.
	ConfirmationClaim *ConfirmationClaim `json:"cnf,omitempty"`
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

	// AuthorizedParty is the azp claim identifying the party the token was
	// issued to. For tokens produced by On-Behalf-Of / Token Exchange
	// (RFC 8693) it is the client that performed the exchange, and it
	// typically matches the current actor's subject (Act.Subject).
	AuthorizedParty string `json:"azp,omitempty"`

	// OrgID is the org_id claim. When the exchanged token is organization
	// bound, this carries the organization the request is scoped to.
	OrgID string `json:"org_id,omitempty"`

	// OrgName is the org_name claim, the human-readable organization name
	// that accompanies OrgID when present.
	OrgName string `json:"org_name,omitempty"`

	// Act is the act (actor) claim as defined by RFC 8693 §4.1. It is
	// populated for tokens issued via On-Behalf-Of / Token Exchange and is
	// nil for ordinary Bearer tokens. Use ValidatedClaims.CurrentActor for
	// access-control decisions; the nested chain is informational only.
	Act *Actor `json:"act,omitempty"`
}

// Actor represents the act (actor) claim from RFC 8693 §4.1. It identifies a
// party that is acting on behalf of the token's subject. Actors nest through
// the Act field to describe a delegation chain, where the outermost actor is
// the current (most recent) actor and inner actors are prior parties.
//
// Per RFC 8693 §4.1, only the current actor (the outermost act.sub) may be
// used for access-control decisions. Nested actors are informational and are
// intended for audit and logging only.
type Actor struct {
	// Subject is the actor's sub claim, identifying the acting party.
	Subject string `json:"sub,omitempty"`

	// Issuer is the actor's optional iss claim. RFC 8693 permits an actor to
	// carry its own issuer; Auth0-issued tokens usually omit it.
	Issuer string `json:"iss,omitempty"`

	// Act is the prior actor in the delegation chain. It is informational
	// only and MUST NOT be used for access-control decisions.
	Act *Actor `json:"act,omitempty"`
}

// CustomClaims defines any custom data / claims wanted.
// The Validator will call the Validate function which
// is where custom validation logic can be defined.
type CustomClaims interface {
	Validate(context.Context) error
}

// ConfirmationClaim represents the cnf (confirmation) claim per RFC 7800 and RFC 9449.
// It contains the JWK SHA-256 thumbprint that binds the access token to a specific key pair.
// This is used for DPoP (Demonstrating Proof-of-Possession) token binding.
type ConfirmationClaim struct {
	// JKT is the JWK SHA-256 Thumbprint (base64url-encoded).
	// This thumbprint must match the JKT calculated from the DPoP proof's JWK.
	JKT string `json:"jkt"`
}

// GetConfirmationJKT returns the jkt from the cnf claim, or empty string if not present.
// This method implements the core.TokenClaims interface.
func (v *ValidatedClaims) GetConfirmationJKT() string {
	if v.ConfirmationClaim == nil {
		return ""
	}
	return v.ConfirmationClaim.JKT
}

// HasConfirmation returns true if the token has a cnf claim.
// This method implements the core.TokenClaims interface.
func (v *ValidatedClaims) HasConfirmation() bool {
	return v.ConfirmationClaim != nil && v.ConfirmationClaim.JKT != ""
}

// HasActor reports whether the token carries an act (actor) claim, which is
// the case for tokens issued via On-Behalf-Of / Token Exchange (RFC 8693).
func (v *ValidatedClaims) HasActor() bool {
	return v.RegisteredClaims.Act != nil && v.RegisteredClaims.Act.Subject != ""
}

// CurrentActor returns the subject of the current actor, i.e. the outermost
// act.sub. This identifies the party that performed the most recent token
// exchange and is the ONLY actor value that may be used for access-control
// decisions, per RFC 8693 §4.1. It returns an empty string when the token has
// no actor.
//
// A typical use is checking the current actor against an allowlist:
//
//	if actor := claims.CurrentActor(); actor != "" && !authorized[actor] {
//	    // reject: acting client is not permitted
//	}
func (v *ValidatedClaims) CurrentActor() string {
	if v.RegisteredClaims.Act == nil {
		return ""
	}
	return v.RegisteredClaims.Act.Subject
}

// DelegationChain returns the subjects of every actor in the delegation chain,
// ordered from the current actor to the original one. For a token exchanged
// user -> SPA -> MCP server it returns ["mcp_server_id", "spa_client_id"].
//
// This is intended for audit and logging only. Do NOT use nested actors for
// authorization decisions; per RFC 8693 §4.1 only CurrentActor may drive
// access control. It returns nil when the token has no actor.
func (v *ValidatedClaims) DelegationChain() []string {
	if v.RegisteredClaims.Act == nil {
		return nil
	}

	var chain []string
	for a := v.RegisteredClaims.Act; a != nil; a = a.Act {
		chain = append(chain, a.Subject)
	}
	return chain
}
