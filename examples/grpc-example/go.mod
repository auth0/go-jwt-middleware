module example.com/example

go 1.23

require (
	github.com/auth0/go-jwt-middleware/v2 v2.0.0-00010101000000-000000000000
	github.com/stretchr/testify v1.10.0
	google.golang.org/grpc v1.68.0
	google.golang.org/protobuf v1.36.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/go-jose/go-jose/v4 v4.0.4 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/crypto v0.31.0 // indirect
	golang.org/x/net v0.29.0 // indirect
	golang.org/x/sys v0.28.0 // indirect
	golang.org/x/text v0.21.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20241219192143-6b3ec007d9bb // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/auth0/go-jwt-middleware/v2 => ./../../
