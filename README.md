# express-jwt-policies

Lightweight [JWT][jwt] authentication & authorization middleware for [Express][express].

[![npm version](https://badge.fury.io/js/express-jwt-policies.svg)](https://badge.fury.io/js/express-jwt-policies)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE.txt)

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->


- [Usage](#usage)
  - [Authentication only](#authentication-only)
  - [Authorization only](#authorization-only)
  - [Asynchronous authorization](#asynchronous-authorization)
- [Configuration](#configuration)
  - [Module options](#module-options)
  - [Authentication options](#authentication-options)
  - [Authorization options](#authorization-options)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->



## Usage

**jwt-express-policies** is an opinionated JWT-based authentication &
authorization middleware.  It assumes that:

* Authentication is performed by sending a JWT bearer token in the
  Authorization header.
* Some JWTs may optionally correspond to a resource (e.g. a user in the
  database) that you will need to load.

This module does **not** handle authentication or authorization errors for you.
It simply passes them down the middleware chain, leaving you the responsibility
of responding adequately to the user:

* Authentication errors will have the `status` property set to [401][http-401].
  Properties may also be added by [express-jwt][express-jwt] which is used to
  check the JWT.
* Authorization errors will have the `status` property set to [403][http-403].

```js
const express = require('express');
const jwtExpressPolicies = require('jwt-express-policies');

// Configure the module.
const authorize = jwtExpressPolicies({

  // Provide a function to load the authenticated resource.
  authenticatedResourceLoader: function(req, res, next) {
    new User().where({ id: req.jwtToken.sub }).then(user => {
      req.currentUser = user;
      next();
    }).catch(next);
  },

  // Provide the secret used to sign JWTs.
  jwtSecret: 'changeme'
});

// Create policies.
const stuffPolicy = {

  // Any authenticated user can retrieve stuff.
  canRetrieve: function(req) {
    return req.currentUser;
  },

  // Only admins can create stuff.
  canCreate: function(req) {
    return req.currentUser && req.currentUser.hasRole('admin');
  }
};

// Create your routes and plug in authorization as middleware.
const router = express.Router();

router.get('/protected/stuff',
  authorize(stuffPolicy.canRetrieve),
  function(req, res, next) { /* retrieve implementation */ });

router.post('/protected/stuff',
  authorize(stuffPolicy.canCreate),
  function(req, res, next) { /* create implementation */ });

// Handle authentication/authorization errors.
router.use((err, req, res, next) => {
  res.status(err.status || 500).send(err.message);
});
```

### Authentication only

```js
// Configure the module.
const auth = jwtExpressPolicies({
  // ...
});

router.get('/protected/stuff',
  auth.authenticate(),
  function(req, res, next) { /* retrieve implementation */ });
```

### Authorization only

```js
// Configure the module.
const auth = jwtExpressPolicies({
  // ...
});

// Use the `authenticate` option of the `authorize` function to
router.get('/protected/stuff',
  auth.authorize(policy.canRetrieve, { authenticate: false }),
  function(req, res, next) { /* retrieve implementation */ });
```

### Asynchronous authorization

Policy functions may return a promise to perform asynchronous checks:

```js
const stuffPolicy = {
  canCreate: async function(req) {
    if (!req.currentUser) {
      return false;
    } else {
      const permissions = await fetchUserPermissions(req.currentUser);
      return permissions.indexOf('stuff:create') >= 0;
    }
  }
};
```



## Configuration

### Module options

These options can be passed to the function returned by
`require('jwt-express-policies')` to configure the module:

* `jwtSecret` (string) **required** - The secret used to sign JWTs.

* `jwtRequestProperty` (string) - The property of the request to which the JWT
  should be attached (`jwtToken` by default).

  ```js
  const auth = jwtExpressPolicies({
    jwtSecret: 'changeme',
    jwtRequestProperty: 'token',
    // ...
  });
  ```

* `authenticatedResourceLoader` (function) **required** - An Express middleware
  function that will be called when a valid JWT bearer token is sent in the
  Authorization header. The JWT will be available as the `req.jwtToken`
  property (by default). It should load whatever resource is identified by the
  token (e.g. a user) and attach it to the request (e.g. to the
  `req.currentUser` property) if necessary. You may do nothing but call
  `next()` in this function if the JWT is sufficient and nothing needs to be
  loaded.

  ```js
  const auth = jwtExpressPolicies({
    authenticatedResourceLoader: function(req, res, next) {
      new User().where({ id: req.jwtToken.sub }).then(user => {
        req.currentUser = user;
        next();
      }).catch(next);
    },
    // ...
  });
  ```

* `authenticationRequired` (boolean) - If true, successful authentication is
  always required. Otherwise, an unauthenticated request will not cause an
  error. It is true by default. It can be set here at the module level, or
  overridden at every authentication or authorization call.

### Authentication options

These options can be passed when calling the module's `authenticate` function:

* `authenticationRequired` (boolean) - Whether successful authentication is
  required. If true, an error will be passed through the middleware chain if no
  valid JWT is found in the Authorization header. If false, an unauthenticated
  request will not cause an error, but the authenticated resource loader will
  not be called. This defaults to the value of the `authenticationRequired`
  option provided when configuring the module (true by default).

The entire options object (including any custom option you might add) is
attached to the request as `req.authOptions`.

### Authorization options

These options can be passed when calling the `authorize` function (which is
also the function returned by configuring the module):

* `authenticate` (boolean) - Whether to perform authentication before
  authorization. Defaults to true.
* `authenticationRequired` (boolean) - Whether successful authentication is
  required before performing authorization with the policy function. Defaults
  to true.

The entire options object (including any custom option you might add) is
attached to the request as `req.authOptions`.



[express]: https://expressjs.com
[express-jwt]: https://github.com/auth0/express-jwt
[http-401]: https://httpstatuses.com/401
[http-403]: https://httpstatuses.com/403
[jwt]: https://jwt.io
