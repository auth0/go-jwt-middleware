module example.com/echo

go 1.24.0

toolchain go1.24.8

require (
	github.com/auth0/go-jwt-middleware/v3 v3.0.0
	github.com/labstack/echo/v4 v4.13.4
)

replace github.com/auth0/go-jwt-middleware/v3 => ./../../

require (
	github.com/labstack/gommon v0.4.2 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fasttemplate v1.2.2 // indirect
	golang.org/x/crypto v0.45.0 // indirect
	golang.org/x/net v0.47.0 // indirect
	golang.org/x/sys v0.38.0 // indirect
	golang.org/x/text v0.31.0 // indirect
	gopkg.in/go-jose/go-jose.v2 v2.6.3 // indirect
)
