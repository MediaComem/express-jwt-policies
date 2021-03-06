const compose = require('composable-middleware');
const jwt = require('express-jwt');

// Returns a function that can be used as an authentication & authorization middleware.
//
// Options:
//
// * `jwtSecret` (string) **required** - The secret used to sign JWTs.
//
// * `jwtRequestProperty` (string) - The property of the request to which the JWT should be
//   attached ("jwtToken" by default).
//
// * `authenticatedResourceLoader` (function) **required** - An Express middleware function that
//   will be called when a valid JWT bearer token is sent in the Authorization header. The JWT will
//   be available as the `req.jwtToken` property (by default). It should load whatever resource is
//   identified by the token (e.g. a user) and attach it to the request (e.g. to the `req.currentUser`
//   property). You may do nothing but call `next()` in this function if the JWT is sufficient and
//   nothing needs to be loaded.
//
// * `authenticationErrorHandler` (function) - An optional Express error-handling middleware function
//   that will be called if an authentication error occurs. This may be due to an invalid JWT, or to
//   a missing JWT if `authenticationRequired` is true. You may handle or transform the error to fit
//   your application.
//
// * `authenticationRequired` (boolean) - If true, successful authentication is always required.
//   Otherwise, an unauthenticated request will not cause an error. It is true by default. It can be
//   set here at the module level, or overridden at every authentication or authorization call.
module.exports = function(options) {
  if (!options) {
    throw new Error('Middleware options are required');
  }

  const authenticatedResourceLoader = options.authenticatedResourceLoader;
  if (typeof(authenticatedResourceLoader) != 'function') {
    throw new Error('The "authenticatedResourceLoader" option must be an Express middleware function');
  }

  const authenticationErrorHandler = options.authenticationErrorHandler;
  const authenticationRequired = options.authenticationRequired !== undefined ? !!options.authenticationRequired : true;

  const jwtSecret = options.jwtSecret;
  if (!jwtSecret) {
    throw new Error('The "jwtSecret" option is required');
  }

  const jwtRequestProperty = options.jwtRequestProperty || 'jwtToken';

  const authorizationErrorHandler = options.authorizationErrorHandler;

  const middleware = authorize;
  middleware.authenticate = authenticate;
  middleware.authorize = authorize;

  return middleware;

  // Authenticates a resource (e.g. a user) through a JWT Bearer token in the Authorization header.
  // This calls the authenticated resource loader provided when configuring the module, which may
  // attach properties to the request, e.g. `req.currentUser`.
  //
  // Options:
  //
  // * `authenticationRequired` (boolean) - Whether authentication is required. If true, an error will
  //   be passed through the middleware chain if no valid JWT is found in the Authorization header. If
  //   false, an unauthenticated request will not cause an error, but the authenticated resource loader
  //   will not be called. This defaults to the value of the `authenticationRequired` option provided
  //   when configuring this module (true by default).
  //
  // The entire options object (including any custom option you might add) is attached to the request
  // as `req.authOptions`.
  function authenticate(options) {
    if (!options) {
      options = {};
    }

    // Require a JWT if specified in the function's or module's options.
    let jwtRequired = authenticationRequired;
    if (options.authenticationRequired !== undefined) {
      jwtRequired = !!options.authenticationRequired;
    }

    let chain = compose()
      // Enrich the request with the authentication options.
      .use(enrichRequest(options))
      // Parse the JWT bearer token, if any.
      .use(validateJwt(jwtRequired))
      // Add the 401 status to the JWT error, if any.
      .use(enrichJwtError)
      // Run the provided function to load the authenticated resource.
      .use((req, res, next) => {
        if (req.jwtToken) {
          authenticatedResourceLoader(req, res, next);
        } else {
          next();
        }
      });

    // Plug in the provided authentication error handler, if any.
    if (authenticationErrorHandler) {
      chain = chain.use((err, req, res, next) => authenticationErrorHandler(err, req, res, next));
    }

    return chain;
  }

  // Ensures that the currently authenticated resource (e.g. a user) is authorized to perform the request by
  // using a policy function. The policy function is called with the request object as its first argument, and
  // has the responsibility to check that everything is in order and return true if the request should be
  // authorized, or false otherwise. Authentication is performed first (by default), so the provided
  // authenticated resource loader will have run and may have attached a resource to the request (e.g.
  // `req.currentUser`).
  //
  // By default, authentication is optional when called during authorization, meaning that an unauthenticated
  // request will pass through to the authorization step, and that it is the responsibility of the policy
  // function to ensure that the request is actually authenticated (e.g. by checking `req.currentUser`). To
  // change this behavior, set the `authenticationRequired` option in this function or when configuring the
  // module.
  //
  // Options:
  //
  // * `authenticate` (boolean) - Whether to perform authentication before authorization. Defaults to true.
  // * `authenticationRequired` (boolean) - Whether successful authentication is required before performing
  //   authorization with the policy function. Defaults to true.
  //
  // The entire options object (including any custom option you might add) is attached to the request
  // as `req.authOptions`. It is also passed to the authentication function.
  function authorize(policy, options) {
    if (typeof(policy) !== 'function') {
      throw new Error('Policy must be a function');
    } else if (!options) {
      options = {};
    }

    let chain = compose();

    // Perform authentication (if enabled).
    const performAuthentication = options.authenticate === undefined || options.authenticate;
    if (performAuthentication) {
      chain = chain.use(authenticate(options));
    }

    // Enrich the request with the authorization options (overwrites the authentication options).
    chain = chain.use(enrichRequest(options));

    // Perform authorization by calling the policy function.
    chain = chain.use(function(req, res, next) {
      Promise.resolve(req).then(policy).then(authorized => {
        if (!authorized) {
          throw authError(403, 'You are not authorized to access this resource.');
        }
      }).then(next, next);
    });

    // Plug in in the provided authorization error handler, if any.
    if (authorizationErrorHandler) {
      chain = chain.use((err, req, res, next) => authorizationErrorHandler(err, req, res, next));
    }

    return chain;
  }

  function validateJwt(required) {
    return jwt({
      credentialsRequired: required,
      requestProperty: jwtRequestProperty,
      secret: jwtSecret
    });
  }

  function enrichJwtError(err, req, res, next) {
    err.status = 401;
    next(err);
  }

  function enrichRequest(options) {
    return function(req, res, next) {
      req.authOptions = options;
      next();
    };
  }

  function authError(status, message) {
    const authError = new Error(message);
    authError.status = status;
    throw authError;
  }
}
