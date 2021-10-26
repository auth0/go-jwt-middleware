package jwtmiddleware

// Option is how options for the middleware are setup.
type Option func(*JWTMiddleware)

// WithCredentialsOptional sets up if credentials are optional or not. If set
// to true then an empty token will be considered valid.
// Default value: false
func WithCredentialsOptional(value bool) Option {
	return func(m *JWTMiddleware) {
		m.credentialsOptional = value
	}
}

// WithValidateOnOptions sets up if OPTIONS requests should have their JWT
// validated or not.
// Default: true
func WithValidateOnOptions(value bool) Option {
	return func(m *JWTMiddleware) {
		m.validateOnOptions = value
	}
}

// WithErrorHandler sets the handler which is called when there are errors in
// the middleware. See the ErrorHandler type for more information.
// Default value: DefaultErrorHandler
func WithErrorHandler(h ErrorHandler) Option {
	return func(m *JWTMiddleware) {
		m.errorHandler = h
	}
}

// WithTokenExtractor sets up the function which extracts the JWT to be
// validated from the request.
// Default: AuthHeaderTokenExtractor
func WithTokenExtractor(e TokenExtractor) Option {
	return func(m *JWTMiddleware) {
		m.tokenExtractor = e
	}
}
