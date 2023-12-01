# Change Log

## [v2.2.0](https://github.com/auth0/go-jwt-middleware/tree/v2.2.0) (2023-12-01)
[Full Changelog](https://github.com/auth0/go-jwt-middleware/compare/v2.1.0...v2.2.0)

**Added**
- add echo example [\#208](https://github.com/auth0/go-jwt-middleware/pull/208) ([mehulgohil](https://github.com/mehulgohil))
- added example for iris web framework [\#199](https://github.com/auth0/go-jwt-middleware/pull/199) ([mehulgohil](https://github.com/mehulgohil))

**Changed**
- ESD-32688: Improve locking and blocking associated with key retrieval [\#225](https://github.com/auth0/go-jwt-middleware/pull/225) ([ewanharris](https://github.com/ewanharris))
- Replace deprecated pkg/errors in favor of Go's standard library [\#189](https://github.com/auth0/go-jwt-middleware/pull/189) ([molaga](https://github.com/molaga))
- Replace square/go-jose with go-jose/go-jose [\#188](https://github.com/auth0/go-jwt-middleware/pull/188) ([sergiught](https://github.com/sergiught))
- Fail to instantiate validator when audience is an empty string [\#183](https://github.com/auth0/go-jwt-middleware/pull/183) ([sergiught](https://github.com/sergiught))

<a name="v2.1.0"></a>
## [v2.1.0](https://github.com/auth0/go-jwt-middleware/tree/v2.1.0) (2022-11-02)

[Full Changelog](https://github.com/auth0/go-jwt-middleware/compare/v2.0.1...v2.1.0)

### Added

* Allow setting a custom `http.Client` on the `jwks.Provider` ([#151](https://github.com/auth0/go-jwt-middleware/pull/146))
* Add example tests ([#157](https://github.com/auth0/go-jwt-middleware/pull/157))
* Add example for the `gin` web framework ([#175](https://github.com/auth0/go-jwt-middleware/pull/175))

### Fixed

* Fix `CookieTokenExtractor` to not throw error when no cookie present ([#172](https://github.com/auth0/go-jwt-middleware/pull/172))
* Fix panic threat when using type-cast for `customClaims` in `validator` ([#165](https://github.com/auth0/go-jwt-middleware/pull/165))
* Fix authentication error when setting multiple audiences on `validator` ([#176](https://github.com/auth0/go-jwt-middleware/pull/176)) 


<a name="v2.0.1"></a>
## [v2.0.1](https://github.com/auth0/go-jwt-middleware/tree/v2.0.1) (2022-03-21)

[Full Changelog](https://github.com/auth0/go-jwt-middleware/compare/v2.0.0...v2.0.1)

### Security

* Update Crypto dependency ([#146](https://github.com/auth0/go-jwt-middleware/pull/146))


<a name="v2.0.0"></a>
## [v2.0.0](https://github.com/auth0/go-jwt-middleware/tree/v2.0.0) (2022-01-19)

[Full Changelog](https://github.com/auth0/go-jwt-middleware/compare/v1.0.1...v2.0.0)

**BEFORE YOU UPGRADE**

- This is a major release that includes breaking changes. Please see [MIGRATION_GUIDE](MIGRATION_GUIDE.md) before
  upgrading. This release will require changes to your application.

### Added

* Use github.com/pkg/errors ([#98](https://github.com/auth0/go-jwt-middleware/issues/98))
* Add a migration guide ([#99](https://github.com/auth0/go-jwt-middleware/issues/99))
* Add cookie token extractor ([#93](https://github.com/auth0/go-jwt-middleware/issues/93), [#63](https://github.com/auth0/go-jwt-middleware/issues/63))
* Add token validator using square/go-jose.v2 ([#84](https://github.com/auth0/go-jwt-middleware/issues/84), [#81](https://github.com/auth0/go-jwt-middleware/issues/81), [#79](https://github.com/auth0/go-jwt-middleware/issues/79), [#74](https://github.com/auth0/go-jwt-middleware/issues/74), [#53](https://github.com/auth0/go-jwt-middleware/issues/53))
* Add allowed signing algorithms in validator ([#128](https://github.com/auth0/go-jwt-middleware/pull/128))
* Add issuer and audience as required params in validator ([#119](https://github.com/auth0/go-jwt-middleware/pull/119))
* Add support for jwks

### Changed

* Update docs ([#72](https://github.com/auth0/go-jwt-middleware/issues/72))
* Reorganize imports across the project
* Reorder fields to use less memory
* Split jwtmiddleware into multiple files

### Breaking

* Simplify JWT library functionality into an interface ([#77](https://github.com/auth0/go-jwt-middleware/issues/77))
* Rename Claims to RegisteredClaims in validator pkg
* Refactor main middleware ([#90](https://github.com/auth0/go-jwt-middleware/issues/90), [#51](https://github.com/auth0/go-jwt-middleware/issues/51), [#51](https://github.com/auth0/go-jwt-middleware/issues/52))
* Write back error messages on DefaultErrorHandler

### Fixed

* Fix code smells and code style


<a name="v2.0.0-beta.1"></a>
## [v2.0.0-beta.1](https://github.com/auth0/go-jwt-middleware/tree/v2.0.0-beta.1) (2022-01-06)

[Full Changelog](https://github.com/auth0/go-jwt-middleware/compare/v2.0.0-beta...v2.0.0-beta.1)

### Changed

* Improved how we pass CustomClaims to Validator for concurrent scenarios ([#134](https://github.com/auth0/go-jwt-middleware/pull/134))

<a name="v2.0.0-beta"></a>
## [v2.0.0-beta](https://github.com/auth0/go-jwt-middleware/tree/v2.0.0-beta) (2021-12-08)

[Full Changelog](https://github.com/auth0/go-jwt-middleware/compare/v1.0.1...v2.0.0-beta)

**BEFORE YOU UPGRADE**

- This is a major release that includes breaking changes. Please see [MIGRATION_GUIDE](MIGRATION_GUIDE.md) before
upgrading. This release will require changes to your application.

### Added

* Use github.com/pkg/errors ([#98](https://github.com/auth0/go-jwt-middleware/issues/98))
* Add a migration guide ([#99](https://github.com/auth0/go-jwt-middleware/issues/99))
* Add cookie token extractor ([#93](https://github.com/auth0/go-jwt-middleware/issues/93), [#63](https://github.com/auth0/go-jwt-middleware/issues/63))
* Add token validator using square/go-jose.v2 ([#84](https://github.com/auth0/go-jwt-middleware/issues/84), [#81](https://github.com/auth0/go-jwt-middleware/issues/81), [#79](https://github.com/auth0/go-jwt-middleware/issues/79), [#74](https://github.com/auth0/go-jwt-middleware/issues/74), [#53](https://github.com/auth0/go-jwt-middleware/issues/53))
* Add allowed signing algorithms in validator ([#128](https://github.com/auth0/go-jwt-middleware/pull/128))
* Add issuer and audience as required params in validator ([#119](https://github.com/auth0/go-jwt-middleware/pull/119))
* Add support for jwks

### Changed

* Update docs ([#72](https://github.com/auth0/go-jwt-middleware/issues/72))
* Reorganize imports across the project
* Reorder fields to use less memory
* Split jwtmiddleware into multiple files

### Breaking

* Simplify JWT library functionality into an interface ([#77](https://github.com/auth0/go-jwt-middleware/issues/77))
* Rename Claims to RegisteredClaims in validator pkg
* Refactor main middleware ([#90](https://github.com/auth0/go-jwt-middleware/issues/90), [#51](https://github.com/auth0/go-jwt-middleware/issues/51), [#51](https://github.com/auth0/go-jwt-middleware/issues/52))
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
