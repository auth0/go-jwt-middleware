package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
)

// WellKnownEndpoints holds the well known OIDC endpoints.
type WellKnownEndpoints struct {
	JWKSURI string `json:"jwks_uri"`
}

// GetWellKnownEndpointsFromIssuerURL gets the well known endpoints for the passed in issuer url.
func GetWellKnownEndpointsFromIssuerURL(
	ctx context.Context,
	httpClient *http.Client,
	issuerURL url.URL,
) (*WellKnownEndpoints, error) {
	issuerURL.Path = path.Join(issuerURL.Path, ".well-known/openid-configuration")

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, issuerURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("could not build request to get well known endpoints: %w", err)
	}

	response, err := httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("could not get well known endpoints from url %s: %w", issuerURL.String(), err)
	}
	defer response.Body.Close()

	var wkEndpoints WellKnownEndpoints
	if err = json.NewDecoder(response.Body).Decode(&wkEndpoints); err != nil {
		return nil, fmt.Errorf("could not decode json body when getting well known endpoints: %w", err)
	}

	return &wkEndpoints, nil
}
