'use strict'

const assert = require('node:assert')
const fp = require('fastify-plugin')
const CSRF = require('@fastify/csrf')
const createError = require('@fastify/error')
const FindMyWay = require('find-my-way')

const MissingCSRFSecretError = createError('FST_CSRF_MISSING_SECRET', 'Missing csrf secret', 403)
const InvalidCSRFTokenError = createError('FST_CSRF_INVALID_TOKEN', 'Invalid csrf token', 403)

const HTTP_METHODS = ['DELETE', 'GET', 'HEAD', 'OPTIONS', 'PATCH', 'POST', 'PUT', 'QUERY', 'TRACE']
const SAFE_METHODS = ['GET', 'HEAD', 'OPTIONS', 'TRACE']

const defaultOptions = {
  cookieKey: '_csrf',
  cookieOpts: { path: '/', sameSite: true, httpOnly: true },
  sessionKey: '_csrf',
  getToken: getTokenDefault,
  getUserInfo: getUserInfoDefault,
  sessionPlugin: '@fastify/cookie',
  logLevel: 'warn',
  routePolicies: []
}

async function fastifyCsrfProtection (fastify, opts) {
  const {
    cookieKey,
    cookieOpts,
    sessionKey,
    getToken,
    getUserInfo,
    sessionPlugin,
    logLevel,
    routePolicies
  } = Object.assign({}, defaultOptions, opts)

  const csrfOpts = opts?.csrfOpts ? opts.csrfOpts : {}

  assert(typeof cookieKey === 'string', 'cookieKey should be a string')
  assert(typeof sessionKey === 'string', 'sessionKey should be a string')
  assert(typeof getToken === 'function', 'getToken should be a function')
  assert(typeof getUserInfo === 'function', 'getUserInfo should be a function')
  assert(typeof cookieOpts === 'object', 'cookieOpts should be a object')
  assert(typeof logLevel === 'string', 'logLevel should be a string')
  assert(
    ['@fastify/cookie', '@fastify/session', '@fastify/secure-session'].includes(sessionPlugin),
    "sessionPlugin should be one of the following: '@fastify/cookie', '@fastify/session', '@fastify/secure-session'"
  )
  assert(Array.isArray(routePolicies), 'routePolicies should be an array')

  if (opts.getUserInfo) {
    csrfOpts.userInfo = true
  }

  if (sessionPlugin === '@fastify/cookie' && csrfOpts.userInfo) {
    assert(csrfOpts.hmacKey, 'csrfOpts.hmacKey is required')
  }

  const tokens = new CSRF(csrfOpts)

  const isCookieSigned = cookieOpts?.signed

  if (sessionPlugin === '@fastify/secure-session') {
    fastify.decorateReply('generateCsrf', generateCsrfSecureSession)
  } else if (sessionPlugin === '@fastify/session') {
    fastify.decorateReply('generateCsrf', generateCsrfSession)
  } else {
    fastify.decorateReply('generateCsrf', generateCsrfCookie)
  }

  fastify.decorate('csrfProtection', csrfProtection)

  let getSecret

  if (sessionPlugin === '@fastify/secure-session') {
    getSecret = function getSecret (req, _reply) { return req.session.get(sessionKey) }
  } else if (sessionPlugin === '@fastify/session') {
    getSecret = function getSecret (req, _reply) { return req.session[sessionKey] }
  } else {
    getSecret = function getSecret (req, reply) {
      return isCookieSigned
        ? reply.unsignCookie(req.cookies[cookieKey] || '').value
        : req.cookies[cookieKey]
    }
  }

  function generateCsrfCookie (opts) {
    let secret = isCookieSigned
      ? this.unsignCookie(this.request.cookies[cookieKey] || '').value
      : this.request.cookies[cookieKey]
    const userInfo = opts ? opts.userInfo : undefined
    if (!secret) {
      secret = tokens.secretSync()
      this.setCookie(cookieKey, secret, Object.assign({}, cookieOpts, opts))
    }
    return tokens.create(secret, userInfo)
  }

  function generateCsrfSecureSession (opts) {
    let secret = this.request.session.get(sessionKey)
    if (!secret) {
      secret = tokens.secretSync()
      this.request.session.set(sessionKey, secret)
    }
    const userInfo = opts ? opts.userInfo : undefined
    if (opts) {
      this.request.session.options(opts)
    }
    return tokens.create(secret, userInfo)
  }

  function generateCsrfSession (opts) {
    let secret = this.request.session[sessionKey]
    const userInfo = opts ? opts.userInfo : undefined
    if (!secret) {
      secret = tokens.secretSync()
      this.request.session[sessionKey] = secret
    }
    return tokens.create(secret, userInfo)
  }

  function csrfProtection (req, reply, next) {
    const secret = getSecret(req, reply)
    if (!secret) {
      req.log[logLevel]('Missing csrf secret')
      return reply.send(new MissingCSRFSecretError())
    }
    if (!tokens.verify(secret, getToken(req), getUserInfo(req))) {
      req.log[logLevel]('Invalid csrf token')
      return reply.send(new InvalidCSRFTokenError())
    }
    next()
  }

  if (routePolicies.length > 0) {
    const { router: policyRouter, entries: policyEntries } = buildPolicyRouter(routePolicies)
    const registeredRoutes = new Set()

    fastify.addHook('onRoute', (routeOptions) => {
      const methods = Array.isArray(routeOptions.method)
        ? routeOptions.method
        : [routeOptions.method]
      for (const method of methods) {
        registeredRoutes.add(`${method} ${routeOptions.url}`)
      }
    })

    fastify.addHook('onReady', function validateRoutePolicies () {
      for (const policy of policyEntries) {
        const pattern = compileRoutePattern(policy.url)
        for (const method of policy.methods) {
          assert(
            matchesRegisteredRoute(registeredRoutes, method, pattern),
            `routePolicies entry for ${method} ${policy.url} does not match a registered route`
          )
        }
      }
    })

    fastify.addHook('onRequest', function csrfRoutePolicy (req, reply, next) {
      if (SAFE_METHODS.includes(req.method)) {
        return next()
      }

      const policy = policyRouter.find(req.method, req.url)?.store
      if (policy === undefined) {
        return csrfProtection(req, reply, next)
      }

      if (policy.policy === 'exempt') {
        req.log[logLevel](`CSRF protection exempt for ${req.method} ${policy.url}: ${policy.reason}`)
        return next()
      }

      return csrfProtection(req, reply, next)
    })
  }
}

function normalizePolicyMethods (method) {
  if (method === undefined) {
    return HTTP_METHODS
  }

  const methods = Array.isArray(method) ? method : [method]
  assert(methods.length > 0, 'routePolicies entry methods should not be an empty array')

  return methods.map((entry) => {
    assert(typeof entry === 'string', 'routePolicies entry methods should be a string or an array of strings')
    const normalized = entry.toUpperCase()
    assert(
      HTTP_METHODS.includes(normalized),
      `routePolicies entry method '${entry}' is not a valid HTTP method`
    )
    return normalized
  })
}

function compileRoutePattern (url) {
  const source = url
    .replace(/[.+?^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '.*')
    .replace(/:[A-Za-z0-9_]+/g, '[^/]+')
  return new RegExp(`^${source}$`)
}

function matchesRegisteredRoute (registeredRoutes, method, pattern) {
  const prefix = `${method} `
  for (const route of registeredRoutes) {
    if (route.startsWith(prefix) && pattern.test(route.slice(prefix.length))) {
      return true
    }
  }
  return false
}

function buildPolicyRouter (routePolicies) {
  const router = new FindMyWay()
  const entries = []

  for (const policy of routePolicies) {
    assert(policy !== null && typeof policy === 'object', 'routePolicies entries should be objects')
    assert(typeof policy.url === 'string' && policy.url.length > 0, 'routePolicies entry url should be a non-empty string')
    assert(
      policy.policy === 'require' || policy.policy === 'exempt',
      "routePolicies entry policy should be either 'require' or 'exempt'"
    )

    if (policy.policy === 'exempt') {
      assert(
        typeof policy.reason === 'string' && policy.reason.length > 0,
        "routePolicies 'exempt' entries require a non-empty 'reason' string"
      )
    } else {
      assert(
        policy.reason === undefined,
        "routePolicies 'reason' is only allowed for 'exempt' entries"
      )
    }

    const methods = normalizePolicyMethods(policy.method)
    const entry = { url: policy.url, policy: policy.policy, methods }
    if (policy.policy === 'exempt') {
      entry.reason = policy.reason
    }
    entries.push(entry)
    router.on(methods, entry.url, () => {}, entry)
  }

  return { router, entries }
}

function getTokenDefault (req) {
  return req.body?._csrf ||
    req.headers['csrf-token'] ||
    req.headers['xsrf-token'] ||
    req.headers['x-csrf-token'] ||
    req.headers['x-xsrf-token']
}

function getUserInfoDefault (_req) {
  return undefined
}

module.exports = fp(fastifyCsrfProtection, {
  fastify: '5.x',
  name: '@fastify/csrf-protection'
})
module.exports.default = fastifyCsrfProtection
module.exports.fastifyCsrfProtection = fastifyCsrfProtection
