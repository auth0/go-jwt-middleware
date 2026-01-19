package main

import (
	"testing"

	"github.com/kataras/iris/v12/httptest"
)

func TestIrisExample_PublicEndpoint(t *testing.T) {
	app := setupApp()
	e := httptest.New(t, app)

	e.GET("/api/public").
		Expect().
		Status(httptest.StatusOK).
		JSON().Object().
		ContainsKey("message").
		ValueEqual("message", "Hello from a public endpoint!")
}

func TestIrisExample_ValidToken(t *testing.T) {
	app := setupApp()
	e := httptest.New(t, app)

	// Valid token from the example
	validToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnby1qd3QtbWlkZGxld2FyZS1leGFtcGxlIiwiYXVkIjoiYXVkaWVuY2UtZXhhbXBsZSIsInN1YiI6IjEyMzQ1Njc4OTAiLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjIsInVzZXJuYW1lIjoidXNlcjEyMyJ9.XFhrzWzntyINkgoRt2mb8dES84dJcuOoORdzKfwUX70"

	e.GET("/api/private").
		WithHeader("Authorization", "Bearer "+validToken).
		Expect().
		Status(httptest.StatusOK).
		JSON().Object().
		ContainsKey("RegisteredClaims").
		ContainsKey("CustomClaims")
}

func TestIrisExample_MissingToken(t *testing.T) {
	app := setupApp()
	e := httptest.New(t, app)

	e.GET("/api/private").
		Expect().
		Status(httptest.StatusUnauthorized).
		JSON().Object().
		ContainsKey("message").
		ValueEqual("message", "JWT is invalid.")
}

func TestIrisExample_InvalidToken(t *testing.T) {
	app := setupApp()
	e := httptest.New(t, app)

	e.GET("/api/private").
		WithHeader("Authorization", "Bearer invalid.token.here").
		Expect().
		Status(httptest.StatusUnauthorized).
		JSON().Object().
		ContainsKey("message").
		ValueEqual("message", "JWT is invalid.")
}

func TestIrisExample_WrongIssuer(t *testing.T) {
	app := setupApp()
	e := httptest.New(t, app)

	// Token with wrong issuer
	wrongIssuerToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ3cm9uZy1pc3N1ZXIiLCJhdWQiOiJhdWRpZW5jZS1leGFtcGxlIiwic3ViIjoiMTIzNDU2Nzg5MCIsIm5hbWUiOiJKb2huIERvZSIsImlhdCI6MTUxNjIzOTAyMiwidXNlcm5hbWUiOiJ1c2VyMTIzIn0.8m4cV8KJFmKnHvY4I0F4Y9L8x-vH7RxQ1qvQzc6YZ8M"

	e.GET("/api/private").
		WithHeader("Authorization", "Bearer "+wrongIssuerToken).
		Expect().
		Status(httptest.StatusUnauthorized).
		JSON().Object().
		ContainsKey("message").
		ValueEqual("message", "JWT is invalid.")
}
