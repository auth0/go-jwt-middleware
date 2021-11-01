# Change Log


<a name="v2.0.0"></a>
## [v2.0.0](https://github.com/auth0/go-jwt-middleware/tree/v2.0.0) (2021-11-01)

[Full Changelog](https://github.com/auth0/go-jwt-middleware/compare/v1.0.1...v2.0.0)

### Added

* Use github.com/pkg/errors ([#98](https://github.com/auth0/go-jwt-middleware/issues/98))
* Add a migration guide ([#99](https://github.com/auth0/go-jwt-middleware/issues/99))
* Add cookie token extractor ([#93](https://github.com/auth0/go-jwt-middleware/issues/93), [#63](https://github.com/auth0/go-jwt-middleware/issues/63))
* Add square/go-jose.v2 token validator ([#84](https://github.com/auth0/go-jwt-middleware/issues/84), [#81](https://github.com/auth0/go-jwt-middleware/issues/81), [#79](https://github.com/auth0/go-jwt-middleware/issues/79), [#74](https://github.com/auth0/go-jwt-middleware/issues/74), [#53](https://github.com/auth0/go-jwt-middleware/issues/53))

### Changed

* Update docs ([#72](https://github.com/auth0/go-jwt-middleware/issues/72))
* Update go version in github actions
* Reorganize imports across the project
* Reorder fields to use less memory
* Rearrange files in josev2 pkg
* Improve phrasing in migration guide
* Split jwtmiddleware into multiple files

### Breaking

* Simplify JWT library functionality into an interface ([#77](https://github.com/auth0/go-jwt-middleware/issues/77))
* Rename Claims to RegisteredClaims in josev2 pkg
* Refactor main middleware ([#90](https://github.com/auth0/go-jwt-middleware/issues/90), [#51](https://github.com/auth0/go-jwt-middleware/issues/51), [#51](https://github.com/auth0/go-jwt-middleware/issues/52))
* Bump golang-jwt to v4 ([#73](https://github.com/auth0/go-jwt-middleware/issues/73))
* Write back error messages on DefaultErrorHandler

### Fixed

* Fix code smells and code style

  
<a name="v1.0.1"></a>
## [v1.0.1](https://github.com/auth0/go-jwt-middleware/tree/v1.0.1) (2021-06-21)

[Full Changelog](https://github.com/auth0/go-jwt-middleware/compare/v1.0.0...v1.0.1)

### Added

* Add .github Setup ([#85](https://github.com/auth0/go-jwt-middleware/issues/85))

### Changed

* Update how to handle jwtMiddleware in Martini ([#78](https://github.com/auth0/go-jwt-middleware/issues/78))
* Isolate example-only dependencies ([#94](https://github.com/auth0/go-jwt-middleware/issues/94))

### Fixed

* Fix broken blog link ([#83](https://github.com/auth0/go-jwt-middleware/issues/83))
  
  
<a name="v1.0.0"></a>
## [v1.0.0](https://github.com/auth0/go-jwt-middleware/tree/v1.0.0) (2021-01-06)

### Added

* Add algorithm check as option
* Wrap errors with %w instead of %v ([#68](https://github.com/auth0/go-jwt-middleware/issues/68))
* Use builtin request context
* Support Go modules ([#65](https://github.com/auth0/go-jwt-middleware/issues/65))
* Add a simple function for logging
* Add ability to disable auth for preflight requests
* Add JWT Middleware for Go
* Add valid check
* Add a bunch of different ways to extract a token from a request
* Add additional documentation
* Add Martini example
* Add a test case using negroni

### Changed

* Update FromAuthHeader to use strings.Fields instead of splitting strings by space to make parsing logic more robust
([#11](https://github.com/auth0/go-jwt-middleware/issues/11))
* Replace "github.com/codegangsta/negroni" ([#32](https://github.com/auth0/go-jwt-middleware/issues/32))
* Reformat examples to use new Claims type ([#57](https://github.com/auth0/go-jwt-middleware/issues/57))
* Refactor code to use logf method
* Disabling auth on OPTIONS now default behavior
* Basic cleanups for golint ([#56](https://github.com/auth0/go-jwt-middleware/issues/56))


### Fixed

* Fix CredentialsOptional flag being ignored
* Fix the examples


### Security

* Update jwt-go to v4 to address CVE-2020-26160 ([#69](https://github.com/auth0/go-jwt-middleware/issues/69))
