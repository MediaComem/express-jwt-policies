/* istanbul ignore file */
const { expect } = require('chai');
const express = require('express');
const jwt = require('jsonwebtoken');
const _ = require('lodash');
const { spy, stub } = require('sinon');
const supertest = require('supertest');

const expressJwtPolicies = require('../index');

// Express middleware that does nothing but call the next middleware.
const noopMiddleware = (req, res, next) => next();

describe('express-jwt-policies', () => {
  it('should be a function', () => {
    expect(expressJwtPolicies).to.be.a('function');
  });

  it('should return middleware factory functions', () => {

    const factory = expressJwtPolicies({
      authenticatedResourceLoader: noopMiddleware,
      jwtSecret: 'letmein'
    });

    expect(factory).to.be.a('function');
    expect(factory.authenticate).to.be.a('function');
    expect(factory.authorize).to.equal(factory);
  });

  it('should throw an error if no options are given', () => {
    expect(() => expressJwtPolicies()).to.throw('Middleware options are required');
  });

  it('should throw an error if no authenticated resource loader is specified', () => {
    expect(() => expressJwtPolicies({
      jwtSecret: 'letmein'
    })).to.throw('The "authenticatedResourceLoader" option must be an Express middleware function');
  });

  it('should throw an error if the specified authenticated resource loader is not a function', () => {
    expect(() => expressJwtPolicies({
      authenticatedResourceLoader: 'foo',
      jwtSecret: 'letmein'
    })).to.throw('The "authenticatedResourceLoader" option must be an Express middleware function');
  });

  it ('should throw an error if no JWT secret is given', () => {
    expect(() => expressJwtPolicies({
      authenticatedResourceLoader: noopMiddleware
    })).to.throw('The "jwtSecret" option is required');
  });

  describe('authenticate', () => {
    it('should authenticate a valid JWT', async () => {
      const auth = buildModule();
      const app = buildApp(auth.authenticate());
      await testApp(app, generateToken());
    });

    it('should not authenticate a request without an Authorization header', async () => {
      const auth = buildModule();
      const app = buildApp(auth.authenticate());
      await testAppError(app, false, 401, { code: 'credentials_required', message: 'No authorization token was found' });
    });

    it('should not authenticate a request with an invalid Authorization header', async () => {
      const auth = buildModule();
      const app = buildApp(auth.authenticate());
      await testAppError(app, test => test.set('Authorization', 'foo'), 401, { code: 'credentials_bad_format', message: 'Format is Authorization: Bearer [token]' });
    });

    it('should not authenticate a request with an invalid JWT', async () => {
      const auth = buildModule();
      const app = buildApp(auth.authenticate());
      await testAppError(app, 'foo', 401, { code: 'invalid_token', message: 'jwt malformed' });
    });

    it('should not authenticate a request with an expired JWT', async () => {
      const auth = buildModule();
      const app = buildApp(auth.authenticate());
      const expiredToken = generateToken({ exp: (new Date().getTime() / 1000) - 1 });
      await testAppError(app, expiredToken, 401, { code: 'invalid_token', message: 'jwt expired' });
    });

    it('should not authenticate a request with a JWT signed with the wrong secret', async () => {
      const auth = buildModule();
      const app = buildApp(auth.authenticate());
      const token = generateToken(undefined, 'secret');
      await testAppError(app, token, 401, { code: 'invalid_token', message: 'invalid signature' });
    });

    describe('authenticatedResourceLoader option', () => {
      it('should call the authenticated resource loader', async () => {

        const loader = stub().callsFake((req, res, next) => {
          req.user = { name: 'John Doe' };
          next();
        });

        let resource;
        const testMiddleware = stub().callsFake((req, res, next) => {
          resource = req.user;
          next();
        });

        const auth = buildModule({ authenticatedResourceLoader: loader });
        const app = buildApp(auth.authenticate(), testMiddleware);
        await testApp(app, generateToken());

        expectMiddlewareCalled(loader);
        expect(loader.args[0][0].jwtToken).to.eql({ foo: 'bar' });

        expectMiddlewareCalled(testMiddleware);
        expect(resource).to.eql({ name: 'John Doe' });
      });

      it('should call an asynchronous authenticated resource loader', async () => {

        const loader = stub().callsFake((req, res, next) => {
          req.user = { name: 'Bob Smith' };
          setTimeout(next, 50);
        });

        let resource;
        const testMiddleware = stub().callsFake((req, res, next) => {
          resource = req.user;
          next();
        });

        const auth = buildModule({ authenticatedResourceLoader: loader });
        const app = buildApp(auth.authenticate(), testMiddleware);
        await testApp(app, generateToken());

        expectMiddlewareCalled(loader);
        expect(loader.args[0][0].jwtToken).to.eql({ foo: 'bar' });

        expectMiddlewareCalled(testMiddleware);
        expect(resource).to.eql({ name: 'Bob Smith' });
      });

      it('should not call the authenticated resource loader if authentication is not required and no JWT is sent', async () => {
        const loader = stub().callsArg(2);
        const auth = buildModule({ authenticatedResourceLoader: loader, authenticationRequired: false });
        const app = buildApp(auth.authenticate());
        await testApp(app, false);
        expectMiddlewareNotCalled(loader);
      });

      it('should pass an error down the middleware chain if an error occurs in the authenticated resource loader', async () => {
        const loader = stub().callsFake((req, res, next) => next(new Error('authentication bug')));
        const auth = buildModule({ authenticatedResourceLoader: loader });
        const app = buildApp(auth.authenticate());
        await testAppError(app, generateToken(), 500, { message: 'authentication bug' });
      });
    });

    describe('authenticationErrorHandler option', () => {
      it('should not call the authentication error handler for a valid JWT', async () => {
        const handler = stub().callsArg(3);
        const auth = buildModule({ authenticationErrorHandler: handler });
        const app = buildApp(auth.authenticate());
        await testApp(app, generateToken());
        expectMiddlewareNotCalled(handler);
      });

      it('should call the authentication error handler if provided and an error occurs during authentication', async () => {

        const handler = stub().callsFake((err, req, res, next) => {
          next(new Error(`handled ${err.message}`));
        });

        const auth = buildModule({ authenticationErrorHandler: handler });
        const app = buildApp(auth.authenticate());
        await testAppError(app, 'foo', 500, { message: 'handled jwt malformed' });

        expectErrorMiddlewareCalled(handler);
      });

      it('should let the authentication error handler handle the error if possible', async () => {

        const handler = stub().callsFake((err, req, res, next) => next());
        const auth = buildModule({ authenticationErrorHandler: handler });
        const app = buildApp(auth.authenticate());
        await testApp(app, 'foo');

        expectErrorMiddlewareCalled(handler);
      });
    });

    describe('authenticationRequired option', () => {
      it('should ignore a missing Authorization header if authentication is not required in the module configuration', async () => {
        const auth = buildModule({ authenticationRequired: false });
        const app = buildApp(auth.authenticate());
        await testApp(app, false);
      });

      it('should ignore a missing Authorization header if authentication is not required in the options', async () => {
        const auth = buildModule();
        const app = buildApp(auth.authenticate({ authenticationRequired: false }));
        await testApp(app, false);
      });

      it('should ignore a missing Authorization header if authentication is required in the module configuration but not in the options', async () => {
        const auth = buildModule({ authenticationRequired: true });
        const app = buildApp(auth.authenticate({ authenticationRequired: false }));
        await testApp(app, false);
      });

      it('should not authenticate a request without an Authorization header if authentication is not required in the module configuration but is required in the options', async () => {
        const auth = buildModule({ authenticationRequired: false });
        const app = buildApp(auth.authenticate({ authenticationRequired: true }));
        await testAppError(app, false, 401, { code: 'credentials_required', message: 'No authorization token was found' });
      });

      it('should not ignore an invalid JWT even if authentication is not required', async () => {
        const auth = buildModule({ authenticationRequired: false });
        const app = buildApp(auth.authenticate());
        await testAppError(app, 'foo', 401, { code: 'invalid_token', message: 'jwt malformed' });
      });
    });

    describe('jwtRequestProperty option', () => {
      it('should attach the JWT to "req.jwtToken" by default', async () => {

        let token;
        const testMiddleware = stub().callsFake((req, res, next) => {
          token = req.jwtToken;
          next();
        });

        const auth = buildModule();
        const app = buildApp(auth.authenticate(), testMiddleware);
        await testApp(app, generateToken());

        expectMiddlewareCalled(testMiddleware);
        expect(token).to.eql({ foo: 'bar' });
      });

      it('should attach the JWT to the request property specified by the "jwtRequestProperty" option', async () => {

        let token;
        const testMiddleware = stub().callsFake((req, res, next) => {
          token = req.theToken;
          next();
        });

        const auth = buildModule({ jwtRequestProperty: 'theToken' });
        const app = buildApp(auth.authenticate(), testMiddleware);
        await testApp(app, generateToken());

        expectMiddlewareCalled(testMiddleware);
        expect(token).to.eql({ foo: 'bar' });
      });
    });
  });

  describe('authorize', () => {

    let defaultMessage;
    beforeEach(() => {
      defaultMessage = 'You are not authorized to access this resource.';
    });

    it('should authorize a valid JWT with a policy that returns true', async () => {
      const auth = buildModule();
      const policy = stub().returns(true);
      const app = buildApp(auth.authorize(policy));
      await testApp(app, generateToken());
      expectPolicyCalled(policy);
    });

    it('should not authorize a valid JWT with a policy that returns false', async () => {
      const auth = buildModule();
      const policy = stub().returns(false);
      const app = buildApp(auth.authorize(policy));
      await testAppError(app, generateToken(), 403, defaultMessage);
      expectPolicyCalled(policy);
    });

    it('should not authorize a valid JWT with a policy that returns undefined', async () => {
      const auth = buildModule();
      const policy = stub().returns(undefined);
      const app = buildApp(auth.authorize(policy));
      await testAppError(app, generateToken(), 403, defaultMessage);
      expectPolicyCalled(policy);
    });

    it('should work with an asynchronous policy that returns true', async () => {
      const auth = buildModule();
      const policy = stub().callsFake(() => new Promise(resolve => setTimeout(() => resolve(true), 50)));
      const app = buildApp(auth.authorize(policy));
      await testApp(app, generateToken());
      expectPolicyCalled(policy);
    });

    it('should work with an asynchronous policy that returns false', async () => {
      const auth = buildModule();
      const policy = stub().callsFake(() => new Promise(resolve => setTimeout(() => resolve(false), 50)));
      const app = buildApp(auth.authorize(policy));
      await testAppError(app, generateToken(), 403, defaultMessage);
      expectPolicyCalled(policy);
    });

    it('should throw an error if the policy is not a function', () => {
      const auth = buildModule();
      expect(() => auth.authorize('foo')).to.throw('Policy must be a function');
    });

    it('should pass an error down the middleware chain if an error is thrown in the policy function', async () => {
      const auth = buildModule();
      const policy = stub().throws(() => new Error('authorization bug'));
      const app = buildApp(auth.authorize(policy));
      await testAppError(app, generateToken(), 500, 'authorization bug');
    });

    describe('authenticate option', () => {
      it('should not perform authorization by default if the request is not authenticated', async () => {
        const auth = buildModule();
        const policy = spy();
        const app = buildApp(auth.authorize(policy));
        await testAppError(app, false, 401, { code: 'credentials_required', message: 'No authorization token was found' });
        expectPolicyNotCalled(policy);
      });

      it('should not perform authorization by default if authentication is invalid', async () => {
        const auth = buildModule();
        const policy = spy();
        const app = buildApp(auth.authorize(policy));
        await testAppError(app, 'foo', 401, { code: 'invalid_token', message: 'jwt malformed' });
        expectPolicyNotCalled(policy);
      });

      it('should perform authorization without authentication if specified', async () => {

        const loader = stub().callsArg(2);
        const handler = stub().callsFake((err, req, res, next) => next(err));

        let token;
        const policy = stub().callsFake(req => {
          token = req.jwtToken;
          return true;
        });

        const auth = buildModule({ authenticatedResourceLoader: loader, authenticationErrorHandler: handler });
        const app = buildApp(auth.authorize(policy, { authenticate: false }));
        await testApp(app, false);

        expectMiddlewareNotCalled(loader);
        expectMiddlewareNotCalled(handler);
        expectPolicyCalled(policy);
        expect(token).to.equal(undefined);
      });
    });

    describe('authenticationRequired option', () => {
      it('should perform authorization when no Authorization header is sent if authentication is not required in the module configuration', async () => {
        const auth = buildModule({ authenticationRequired: false });
        const policy = stub().returns(true);
        const app = buildApp(auth.authorize(policy));
        await testApp(app, false);
        expectPolicyCalled(policy);
      });

      it('should not perform authorization if authentication is invalid even when authentication is not required in the module configuration', async () => {
        const auth = buildModule({ authenticationRequired: false });
        const policy = spy();
        const app = buildApp(auth.authorize(policy));
        await testAppError(app, 'foo', 401, { code: 'invalid_token', message: 'jwt malformed' });
        expectPolicyNotCalled(policy);
      });

      it('should perform authorization when no Authorization header is sent if authentication is not required', async () => {
        const auth = buildModule();
        const policy = stub().returns(true);
        const app = buildApp(auth.authorize(policy, { authenticationRequired: false }));
        await testApp(app, false);
        expectPolicyCalled(policy);
      });

      it('should not perform authorization if authentication is invalid even when authentication is not required', async () => {
        const auth = buildModule();
        const policy = spy();
        const app = buildApp(auth.authorize(policy, { authenticationRequired: false }));
        await testAppError(app, 'foo', 401, { code: 'invalid_token', message: 'jwt malformed' });
        expectPolicyNotCalled(policy);
      });
    });

    describe('authorizationErrorHandler option', () => {
      it('should not call the authorization error handler if the request is authorized', async () => {

        const handler = stub().callsArg(3);
        const policy = stub().returns(true);

        const auth = buildModule({ authorizationErrorHandler: handler });
        const app = buildApp(auth.authorize(policy));
        await testApp(app, generateToken());

        expectPolicyCalled(policy);
        expectMiddlewareNotCalled(handler);
      });

      it('should call the authorization error handler if provided and the request is not authorized', async () => {

        const handler = stub().callsFake((err, req, res, next) => {
          next(new Error(`handled ${err.message}`));
        });

        const policy = stub().returns(false);

        const auth = buildModule({ authorizationErrorHandler: handler });
        const app = buildApp(auth.authorize(policy));
        await testAppError(app, generateToken(), 500, { message: `handled ${defaultMessage}` });

        expectPolicyCalled(policy);
        expectErrorMiddlewareCalled(handler);
      });

      it('should call the authorization error handler if provided and an error is thrown during authorization', async () => {

        const handler = stub().callsFake((err, req, res, next) => {
          next(new Error(`handled ${err.message}`));
        });

        const policy = stub().throws(() => new Error('authorization bug'));

        const auth = buildModule({ authorizationErrorHandler: handler });
        const app = buildApp(auth.authorize(policy));
        await testAppError(app, generateToken(), 500, { message: `handled authorization bug` });

        expectPolicyCalled(policy);
        expectErrorMiddlewareCalled(handler);
      });

      it('should let the authorization error handler handle the error if possible', async () => {

        const handler = stub().callsFake((err, req, res, next) => next());
        const policy = stub().returns(false);
        const auth = buildModule({ authorizationErrorHandler: handler });
        const app = buildApp(auth.authorize(policy));
        await testApp(app, generateToken());

        expectPolicyCalled(policy);
        expectErrorMiddlewareCalled(handler);
      });
    });
  });
});

function buildModule(config) {
  return expressJwtPolicies(_.defaults(config, {
    authenticatedResourceLoader: noopMiddleware,
    jwtSecret: 'letmein'
  }));
}

function generateToken(properties = { foo: 'bar' }, secret = 'letmein', options = { noTimestamp: true }) {
  return jwt.sign(properties, secret, options);
}

function buildApp(...middlewares) {
  const app = express();
  app.get('/test', ...middlewares, (req, res) => res.send({ ok: true }));
  app.use((err, req, res, next) => res.status(err.status || 500).send(_.pick(err, 'code', 'message')));
  return app;
}

function testApp(app, token) {

  let test = supertest(app).get('/test');

  if (token) {
    test = test.set('Authorization', `Bearer ${token}`);
  }

  return test.then(res => {
    expect(res.status).to.equal(200);
    expect(res.body).to.eql({ ok: true });
  });
}

function testAppError(app, token, expectedStatus, expectedError) {

  let test = supertest(app).get('/test');

  if (_.isFunction(token)) {
    test = token(test);
  } else if (_.isString(token)) {
    test = test.set('Authorization', `Bearer ${token}`);
  } else if (token) {
    throw new Error(`Unexpected token type ${typeof(token)}; must be a string or a function`);
  }

  return test.then(res => {

    expect(res.status).to.equal(expectedStatus);

    if (_.isString(expectedError)) {
      expect(res.body).to.eql({ message: expectedError });
    } else {
      expect(res.body).to.eql(expectedError);
    }
  });
}

function expectMiddlewareCalled(middlewareSpy) {
  expect(middlewareSpy.called, 'middlewareSpy.called').to.equal(true);
  expect(middlewareSpy.args[0][0].get, 'middlewareSpy.args[0].get').to.be.a('function');
  expect(middlewareSpy.args[0][0].authOptions, 'middlewareSpy.args[0].authOptions').to.be.an('object');
  expect(middlewareSpy.args[0][1].send, 'middlewareSpy.args[1].send').to.be.a('function');
  expect(middlewareSpy.args[0][2], 'middlewareSpy.args[2]').to.be.a('function');
  expect(middlewareSpy.args[0], 'middlewareSpy.args').to.have.lengthOf(3);
  expect(middlewareSpy.calledOnce, 'middlewareSpy.calledOnce').to.equal(true);
}

function expectErrorMiddlewareCalled(middlewareSpy) {
  expect(middlewareSpy.called, 'middlewareSpy.called').to.equal(true);
  expect(middlewareSpy.args[0][0], 'middlewareSpy.args[0]').to.be.an.instanceof(Error);
  expect(middlewareSpy.args[0][1].get, 'middlewareSpy.args[1].get').to.be.a('function');
  expect(middlewareSpy.args[0][1].authOptions, 'middlewareSpy.args[1].authOptions').to.be.an('object');
  expect(middlewareSpy.args[0][2].send, 'middlewareSpy.args[2].send').to.be.a('function');
  expect(middlewareSpy.args[0][3], 'middlewareSpy.args[3]').to.be.a('function');
  expect(middlewareSpy.args[0], 'middlewareSpy.args').to.have.lengthOf(4);
  expect(middlewareSpy.calledOnce, 'middlewareSpy.calledOnce').to.equal(true);
}

function expectMiddlewareNotCalled(middlewareSpy) {
  expect(middlewareSpy.args, 'middlewareSpy.args').to.eql([]);
}

function expectPolicyCalled(policySpy) {
  expect(policySpy.called, 'policySpy.called').to.equal(true);
  expect(policySpy.args[0][0].get, 'policySpy.args[0].get').to.be.a('function');
  expect(policySpy.args[0][0].authOptions, 'policySpy.args[0].authOptions').to.be.an('object');
  expect(policySpy.args[0], 'policySpy.args').to.have.lengthOf(1);
  expect(policySpy.calledOnce, 'policySpy.calledOnce').to.equal(true);
}

function expectPolicyNotCalled(policySpy) {
  expect(policySpy.args, 'policySpy.args').to.eql([]);
}
