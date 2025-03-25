package grpcjwt

// Option is a function that configures a JWTInterceptor.
type Option func(*JWTInterceptor)

// ExclusionChecker is a function that checks if a method should be excluded from JWT validation.
type ExclusionChecker func(method string) bool

// WithCredentialsOptional sets if credentials are optional.
// If set to true, requests without a JWT token will be allowed.
func WithCredentialsOptional(optional bool) Option {
	return func(i *JWTInterceptor) {
		i.credentialsOptional = optional
	}
}

// WithTokenExtractor sets a custom token extractor.
func WithTokenExtractor(extractor GRPCTokenExtractor) Option {
	return func(i *JWTInterceptor) {
		i.tokenExtractor = extractor
	}
}

// WithExclusionMethods configures methods that should be excluded from JWT validation.
func WithExclusionMethods(methods []string) Option {
	return func(i *JWTInterceptor) {
		methodMap := make(map[string]struct{}, len(methods))
		for _, method := range methods {
			methodMap[method] = struct{}{}
		}

		i.exclusionChecker = func(method string) bool {
			_, exists := methodMap[method]
			return exists
		}
	}
}

// WithExclusionChecker sets a custom exclusion checker.
func WithExclusionChecker(checker ExclusionChecker) Option {
	return func(i *JWTInterceptor) {
		i.exclusionChecker = checker
	}
}
