# HTTP JWKS example

This is an example of how to use the http middleware with JWKS.

# Using it

To try this out:
1. Install all dependencies with `go install`
1. Go to https://manage.auth0.com/ and create a new API.
1. Go to the "Test" tab of the API and copy the cURL example.
1. Run the cURL example in your terminal and copy the `access_token` from the response. The tool jq can be helpful for this.
1. In the example change `<your tenant domain>` on line 29 to the domain used in the cURL request.
1. Run the example with `go run main.go`.
1. In a new terminal use cURL to talk to the API: `curl -v --request GET --url http://localhost:3000`
1. Now try it again with the `access_token` you copied earlier and run `curl -v --request GET --url http://localhost:3000 --header "authorization: Bearer $TOKEN"` to see a successful request.
