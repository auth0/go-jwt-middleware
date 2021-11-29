/*
Package validator contains an implementation of jwtmiddleware.ValidateToken using
the Square go-jose package version 2.

The implementation handles some nuances around JWTs and supports:
- a key func to pull the key(s) used to verify the token signature
- verifying the signature algorithm is what it should be
- validation of "regular" claims
- validation of custom claims
- clock skew allowances

When this package is used, tokens are returned as `JSONWebToken` from the
gopkg.in/square/go-jose.v2/jwt package.

Note that while the jose package does support multi-recipient JWTs, this
package does not support them.
*/
package validator
