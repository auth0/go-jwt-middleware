# josev2 examples

These examples should get you up and running and understanding how to best use 
the validator.

You will need `jwt-cli` to work through the examples:
```
npm install --global "@clarketm/jwt-cli"
```

In in terminal, run the example to get started:
```
go run main.go
```
Now you can follow the examples below.

### with clockskew
The example allows clock skew of 30 seconds. Let's use a token that expired 45 
seconds ago to show that it will reject this.
```
export TOKEN=$(jwt sign -n "{\"iat\":$(date -r $(( $(date +%s) - 3645 )) +%s),\"iss\":\"josev2-example\"}" "secret")
curl "127.0.0.1:3000" -H "Authorization: Bearer $TOKEN"
```

Now lets generate a token that expired 15 seconds ago and watch as it is not 
rejected.
```
export TOKEN=$(jwt sign -n "{\"iat\":$(date -r $(( $(date +%s) - 3615 )) +%s),\"iss\":\"josev2-example\"}" "secret")
curl "127.0.0.1:3000" -H "Authorization: Bearer $TOKEN"
```

### custom claims
We can use custom claims in our token and have the validator pass them back to 
us in the user context. When the endpoint responds after a valid request it 
prints out the CustomClaims. Let's add two claims to our token to see that it 
handles the claim we have defined in CustomClaimsExample but does nothing with 
the claim we do not have defined.
```
export TOKEN=$(jwt sign -n "{\"username\":\"user123\",\"hairColor\":\"brown\",\"iss\":\"josev2-example\"}" "secret")
curl "127.0.0.1:3000" -H "Authorization: Bearer $TOKEN"
```
It will print out something like
```json
{
        "CustomClaims": {
                "username": "user123"
        },
        "Claims": {
                "iss": "josev2-example",
                "exp": 1616801896,
                "iat": 1616798296
        }
}
```
As you can see the `username` claim is there, but the `hairColor` claim is not.

### custom validaton
Along with custom claims we can also run custom validation logic to determine 
if the token should be rejected or not. Our example is setup to reject anything 
that has the field `shouldReject` set to `true`.
```
export TOKEN=$(jwt sign -n "{\"shouldReject\":true,\"iss\":\"josev2-example\"}" "secret")
curl "127.0.0.1:3000" -H "Authorization: Bearer $TOKEN"
```
It will print out something like
```
The token isn't valid: custom claims not validated: should reject was set to true
```
The message comes directly from the custom validation!

### expected claims
In all of the above examples we've seen the `iss` field being set. That's 
because it expects the issuer to be `josev2-example`. This validation is built
right into jose. If we remove the field it will error on that field.
```
export TOKEN=$(jwt sign -n "{}" "secret")
curl "127.0.0.1:3000" -H "Authorization: Bearer $TOKEN"
```
It will print out something like
```
The token isn't valid: expected claims not validated: square/go-jose/jwt: validation failed, invalid issuer claim (iss)
```

### JWKS
For a JWKS example please see [examples/http-jwks-example/README.md](../../../examples/http-jwks-example/README.md).

Take a look through the example code and things will make a lot more sense.
