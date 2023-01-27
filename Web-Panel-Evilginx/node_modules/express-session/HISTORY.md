1.17.3 / 2022-05-11
===================

  * Fix resaving already-saved new session at end of request
  * deps: cookie@0.4.2

1.17.2 / 2021-05-19
===================

  * Fix `res.end` patch to always commit headers
  * deps: cookie@0.4.1
  * deps: safe-buffer@5.2.1

1.17.1 / 2020-04-16
===================

  * Fix internal method wrapping error on failed reloads

1.17.0 / 2019-10-10
===================

  * deps: cookie@0.4.0
    - Add `SameSite=None` support
  * deps: safe-buffer@5.2.0

1.16.2 / 2019-06-12
===================

  * Fix restoring `cookie.originalMaxAge` when store returns `Date`
  * deps: parseurl@~1.3.3

1.16.1 / 2019-04-11
===================

  * Fix error passing `data` option to `Cookie` constructor
  * Fix uncaught error from bad session data

1.16.0 / 2019-04-10
===================

  * Catch invalid `cookie.maxAge` value earlier
  * Deprecate setting `cookie.maxAge` to a `Date` object
  * Fix issue where `resave: false` may not save altered sessions
  * Remove `utils-merge` dependency
  * Use `safe-buffer` for improved Buffer API
  * Use `Set-Cookie` as cookie header name for compatibility
  * deps: depd@~2.0.0
    - Replace internal `eval` usage with `Function` constructor
    - Use instance methods on `process` to check for listeners
    - perf: remove argument reassignment
  * deps: on-headers@~1.0.2
    - Fix `res.writeHead` patch missing return value

1.15.6 / 2017-09-26
===================

  * deps: debug@2.6.9
  * deps: parseurl@~1.3.2
    - perf: reduce overhead for full URLs
    - perf: unroll the "fast-path" `RegExp`
  * deps: uid-safe@~2.1.5
    - perf: remove only trailing `=`
  * deps: utils-merge@1.0.1

1.15.5 / 2017-08-02
===================

  * Fix `TypeError` when `req.url` is an empty string
  * deps: depd@~1.1.1
    - Remove unnecessary `Buffer` loading

1.15.4 / 2017-07-18
===================

  * deps: debug@2.6.8

1.15.3 / 2017-05-17
===================

  * deps: debug@2.6.7
    - deps: ms@2.0.0

1.15.2 / 2017-03-26
===================

  * deps: debug@2.6.3
    - Fix `DEBUG_MAX_ARRAY_LENGTH`
  * deps: uid-safe@~2.1.4
    - Remove `base64-url` dependency

1.15.1 / 2017-02-10
===================

  * deps: debug@2.6.1
    - Fix deprecation messages in WebStorm and other editors
    - Undeprecate `DEBUG_FD` set to `1` or `2`

1.15.0 / 2017-01-22
===================

  * Fix detecting modified session when session contains "cookie" property
  * Fix resaving already-saved reloaded session at end of request
  * deps: crc@3.4.4
    - perf: use `Buffer.from` when available
  * deps: debug@2.6.0
    - Allow colors in workers
    - Deprecated `DEBUG_FD` environment variable
    - Use same color for same namespace
    - Fix error when running under React Native
    - deps: ms@0.7.2
  * perf: remove unreachable branch in set-cookie method

1.14.2 / 2016-10-30
===================

  * deps: crc@3.4.1
    - Fix deprecation warning in Node.js 7.x
  * deps: uid-safe@~2.1.3
    - deps: base64-url@1.3.3

1.14.1 / 2016-08-24
===================

  * Fix not always resetting session max age before session save
  * Fix the cookie `sameSite` option to actually alter the `Set-Cookie`
  * deps: uid-safe@~2.1.2
    - deps: base64-url@1.3.2

1.14.0 / 2016-07-01
===================

  * Correctly inherit from `EventEmitter` class in `Store` base class
  * Fix issue where `Set-Cookie` `Expires` was not always updated
  * Methods are no longer enumerable on `req.session` object
  * deps: cookie@0.3.1
    - Add `sameSite` option
    - Improve error message when `encode` is not a function
    - Improve error message when `expires` is not a `Date`
    - perf: enable strict mode
    - perf: use for loop in parse
    - perf: use string concatination for serialization
  * deps: parseurl@~1.3.1
    - perf: enable strict mode
  * deps: uid-safe@~2.1.1
    - Use `random-bytes` for byte source
    - deps: base64-url@1.2.2
  * perf: enable strict mode
  * perf: remove argument reassignment

1.13.0 / 2016-01-10
===================

  * Fix `rolling: true` to not set cookie when no session exists
    - Better `saveUninitialized: false` + `rolling: true` behavior
  * deps: crc@3.4.0

1.12.1 / 2015-10-29
===================

  * deps: cookie@0.2.3
    - Fix cookie `Max-Age` to never be a floating point number

1.12.0 / 2015-10-25
===================

  * Support the value `'auto'` in the `cookie.secure` option
  * deps: cookie@0.2.2
    - Throw on invalid values provided to `serialize`
  * deps: depd@~1.1.0
    - Enable strict mode in more places
    - Support web browser loading
  * deps: on-headers@~1.0.1
    - perf: enable strict mode

1.11.3 / 2015-05-22
===================

  * deps: cookie@0.1.3
    - Slight optimizations
  * deps: crc@3.3.0

1.11.2 / 2015-05-10
===================

  * deps: debug@~2.2.0
    - deps: ms@0.7.1
  * deps: uid-safe@~2.0.0

1.11.1 / 2015-04-08
===================

  * Fix mutating `options.secret` value

1.11.0 / 2015-04-07
===================

  * Support an array in `secret` option for key rotation
  * deps: depd@~1.0.1

1.10.4 / 2015-03-15
===================

  * deps: debug@~2.1.3
    - Fix high intensity foreground color for bold
    - deps: ms@0.7.0

1.10.3 / 2015-02-16
===================

  * deps: cookie-signature@1.0.6
  * deps: uid-safe@1.1.0
    - Use `crypto.randomBytes`, if available
    - deps: base64-url@1.2.1

1.10.2 / 2015-01-31
===================

  * deps: uid-safe@1.0.3
    - Fix error branch that would throw
    - deps: base64-url@1.2.0

1.10.1 / 2015-01-08
===================

  * deps: uid-safe@1.0.2
    - Remove dependency on `mz`

1.10.0 / 2015-01-05
===================

  * Add `store.touch` interface for session stores
  * Fix `MemoryStore` expiration with `resave: false`
  * deps: debug@~2.1.1

1.9.3 / 2014-12-02
==================

  * Fix error when `req.sessionID` contains a non-string value

1.9.2 / 2014-11-22
==================

  * deps: crc@3.2.1
    - Minor fixes

1.9.1 / 2014-10-22
==================

  * Remove unnecessary empty write call
    - Fixes Node.js 0.11.14 behavior change
    - Helps work-around Node.js 0.10.1 zlib bug

1.9.0 / 2014-09-16
==================

  * deps: debug@~2.1.0
    - Implement `DEBUG_FD` env variable support
  * deps: depd@~1.0.0

1.8.2 / 2014-09-15
==================

  * Use `crc` instead of `buffer-crc32` for speed
  * deps: depd@0.4.5

1.8.1 / 2014-09-08
==================

  * Keep `req.session.save` non-enumerable
  * Prevent session prototype methods from being overwritten

1.8.0 / 2014-09-07
==================

  * Do not resave already-saved session at end of request
  * deps: cookie-signature@1.0.5
  * deps: debug@~2.0.0

1.7.6 / 2014-08-18
==================

  * Fix exception on `res.end(null)` calls

1.7.5 / 2014-08-10
==================

  * Fix parsing original URL
  * deps: on-headers@~1.0.0
  * deps: parseurl@~1.3.0

1.7.4 / 2014-08-05
==================

  * Fix response end delay for non-chunked responses

1.7.3 / 2014-08-05
==================

  * Fix `res.end` patch to call correct upstream `res.write`

1.7.2 / 2014-07-27
==================

  * deps: depd@0.4.4
    - Work-around v8 generating empty stack traces

1.7.1 / 2014-07-26
==================

  * deps: depd@0.4.3
    - Fix exception when global `Error.stackTraceLimit` is too low

1.7.0 / 2014-07-22
==================

  * Improve session-ending error handling
    - Errors are passed to `next(err)` instead of `console.error`
  * deps: debug@1.0.4
  * deps: depd@0.4.2
    - Add `TRACE_DEPRECATION` environment variable
    - Remove non-standard grey color from color output
    - Support `--no-deprecation` argument
    - Support `--trace-deprecation` argument

1.6.5 / 2014-07-11
==================

  * Do not require `req.originalUrl`
  * deps: debug@1.0.3
    - Add support for multiple wildcards in namespaces

1.6.4 / 2014-07-07
==================

  * Fix blank responses for stores with synchronous operations

1.6.3 / 2014-07-04
==================

  * Fix resave deprecation message

1.6.2 / 2014-07-04
==================

  * Fix confusing option deprecation messages

1.6.1 / 2014-06-28
==================

  * Fix saveUninitialized deprecation message

1.6.0 / 2014-06-28
==================

  * Add deprecation message to undefined `resave` option
  * Add deprecation message to undefined `saveUninitialized` option
  * Fix `res.end` patch to return correct value
  * Fix `res.end` patch to handle multiple `res.end` calls
  * Reject cookies with missing signatures

1.5.2 / 2014-06-26
==================

  * deps: cookie-signature@1.0.4
    - fix for timing attacks

1.5.1 / 2014-06-21
==================

  * Move hard-to-track-down `req.secret` deprecation message

1.5.0 / 2014-06-19
==================

  * Debug name is now "express-session"
  * Deprecate integration with `cookie-parser` middleware
  * Deprecate looking for secret in `req.secret`
  * Directly read cookies; `cookie-parser` no longer required
  * Directly set cookies; `res.cookie` no longer required
  * Generate session IDs with `uid-safe`, faster and even less collisions

1.4.0 / 2014-06-17
==================

  * Add `genid` option to generate custom session IDs
  * Add `saveUninitialized` option to control saving uninitialized sessions
  * Add `unset` option to control unsetting `req.session`
  * Generate session IDs with `rand-token` by default; reduce collisions
  * deps: buffer-crc32@0.2.3

1.3.1 / 2014-06-14
==================

  * Add description in package for npmjs.org listing

1.3.0 / 2014-06-14
==================

  * Integrate with express "trust proxy" by default
  * deps: debug@1.0.2

1.2.1 / 2014-05-27
==================

  * Fix `resave` such that `resave: true` works

1.2.0 / 2014-05-19
==================

  * Add `resave` option to control saving unmodified sessions

1.1.0 / 2014-05-12
==================

  * Add `name` option; replacement for `key` option
  * Use `setImmediate` in MemoryStore for node.js >= 0.10

1.0.4 / 2014-04-27
==================

  * deps: debug@0.8.1

1.0.3 / 2014-04-19
==================

  *  Use `res.cookie()` instead of `res.setHeader()`
  * deps: cookie@0.1.2

1.0.2 / 2014-02-23
==================

  * Add missing dependency to `package.json`

1.0.1 / 2014-02-15
==================

  * Add missing dependencies to `package.json`

1.0.0 / 2014-02-15
==================

  * Genesis from `connect`
